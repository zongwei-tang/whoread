import Foundation
import WhoReadCore

/// One change to the sensitive-path catalog from Settings → Monitored paths (brief §1: users can
/// add, change and delete entries). The app applies edits to the catalog it fetches from the
/// daemon right before saving, so concurrent changes are not overwritten with a stale copy.
public enum CatalogEdit: Equatable, Sendable {
    case setEnabled(categoryID: String, Bool)
    case setSeverity(categoryID: String, Severity)
    case addPath(categoryID: String, String)
    case removePath(categoryID: String, String)
    /// Adds the path to the `custom` category (created if missing) and enables it.
    case monitorPath(String)
    case addCategory(id: String, name: String, severity: Severity, path: String?)
    /// User categories only (`isUserCategory`).
    case deleteCategory(id: String)

    public static let customCategoryID = "custom"

    /// Categories the user created; the built-in ones can be disabled but not deleted.
    public static func isUserCategory(_ c: CategorySpec) -> Bool {
        c.kind == .custom && c.id != customCategoryID
    }

    /// Project-roots categories take their folders from the Project roots setting.
    public static func pathsEditable(_ c: CategorySpec) -> Bool { c.kind != .projectRoots }

    /// The trimmed path if it is usable as a catalog prefix: absolute or `~/`, and naming more
    /// than the root or a whole home folder (which would put every file access in the pipeline).
    public static func validPath(_ raw: String) -> String? {
        let p = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let rest: Substring
        if p.hasPrefix("~/") {
            rest = p.dropFirst(2)
        } else if p.hasPrefix("/") {
            rest = p.dropFirst(1)
        } else {
            return nil
        }
        return rest.contains(where: { $0 != "/" }) ? p : nil
    }

    public static func newCategoryID() -> String { "custom." + UUID().uuidString.lowercased() }

    /// Applies the edit; edits that do not fit the catalog (unknown category, invalid path,
    /// duplicate id) leave it unchanged.
    public func apply(to catalog: inout Catalog) {
        func index(_ id: String) -> Int? { catalog.categories.firstIndex { $0.id == id } }
        switch self {
        case .setEnabled(let id, let on):
            if let i = index(id) { catalog.categories[i].enabled = on }
        case .setSeverity(let id, let severity):
            if let i = index(id) { catalog.categories[i].severity = severity }
        case .addPath(let id, let raw):
            guard let i = index(id), CatalogEdit.pathsEditable(catalog.categories[i]), let p = CatalogEdit.validPath(raw),
                  !catalog.categories[i].paths.contains(p) else { return }
            catalog.categories[i].paths.append(p)
        case .removePath(let id, let p):
            if let i = index(id) { catalog.categories[i].paths.removeAll { $0 == p } }
        case .monitorPath(let raw):
            guard let p = CatalogEdit.validPath(raw) else { return }
            if index(CatalogEdit.customCategoryID) == nil {
                catalog.categories.append(CategorySpec(
                    id: CatalogEdit.customCategoryID, name: LocalizedText(en: L10n.t(.catCustomName, .en), zhHans: L10n.t(.catCustomName, .zhHans)),
                    kind: .custom, group: "custom", severity: .high, paths: []))
            }
            CatalogEdit.addPath(categoryID: CatalogEdit.customCategoryID, p).apply(to: &catalog)
            CatalogEdit.setEnabled(categoryID: CatalogEdit.customCategoryID, true).apply(to: &catalog)
        case .addCategory(let id, let rawName, let severity, let rawPath):
            let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
            let path = rawPath.flatMap { $0.trimmingCharacters(in: .whitespaces).isEmpty ? nil : $0 }
            guard !name.isEmpty, index(id) == nil else { return }
            var paths: [String] = []
            if let path {
                guard let p = CatalogEdit.validPath(path) else { return }
                paths = [p]
            }
            catalog.categories.append(CategorySpec(id: id, name: LocalizedText(name), kind: .custom, group: "custom",
                                                   severity: severity, paths: paths))
        case .deleteCategory(let id):
            guard let i = index(id), CatalogEdit.isUserCategory(catalog.categories[i]) else { return }
            catalog.categories.remove(at: i)
        }
    }
}

extension Catalog {
    public func applying(_ edits: [CatalogEdit]) -> Catalog {
        var c = self
        for e in edits { e.apply(to: &c) }
        return c
    }
}
