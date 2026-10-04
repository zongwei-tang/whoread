# Part C findings: XcodeGen, SystemExtensions, Endpoint Security, notarytool, NSXPC, Full Disk Access deep link

Fetched 2026-10-04 (UTC). Raw sources are saved under `scratchpad/src-partC/`:
- `xcodegen-*`: XcodeGen docs and source
- `apple/*.json`: Apple DocC JSON (`apple/rendered/*.txt` holds a text rendering made by `tools/docc.py`)
- `man/`: man pages
- `sdk*.h`: SDK headers from a GitHub SDK mirror
- `web/`, `forums/`: third-party pages and forum extractions

Apple developer forum pages could not be downloaded with curl: they redirect to a "Security Verification" page. For those, the files hold WebFetch extractions. WebFetch uses a small model, so those quotes are close to verbatim but not byte-exact. Each such quote is marked "(WebFetch)".

---

## 8. XcodeGen ProjectSpec

**Versions of the sources I fetched**
- `Docs/ProjectSpec.md` came from the `master` branch. The latest commit touching that file is `24c891cb55805a5ee088912b98ee3c3d7121a92f` (2026-09-13, "Add scheme build architecture overrides (#1642)"). The repo HEAD at fetch time was `366592bc5be446b427fc8e2a21520344460f96ab`. (Sources: `gh api repos/yonaskolb/XcodeGen/commits?path=Docs/ProjectSpec.md&per_page=1`; `src-partC/xcodegen-ProjectSpec-commit.json`)
- The latest XcodeGen release is **2.46.0** (published 2026-07-16). (Source: `gh api repos/yonaskolb/XcodeGen/releases/latest`)
- A real-world spec (third-party) uses `minimumXcodeGenVersion: 2.46.0` for a system-extension target. See "Real-world reference" below.
- URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Docs/ProjectSpec.md

### Target `type` values (verbatim list, "Product Type" section)
> This will provide default build settings for a certain product type. It can be any of the following:
```
- `application`
- `application.on-demand-install-capable`
- `application.messages`
- `application.watchapp`
- `application.watchapp2`
- `application.watchapp2-container`
- `app-extension`
- `app-extension.intents-service`
- `app-extension.messages`
- `app-extension.messages-sticker-pack`
- `bundle`
- `bundle.ocunit-test`
- `bundle.ui-testing`
- `bundle.unit-test`
- `extensionkit-extension`
- `framework`
- `instruments-package`
- `library.dynamic`
- `library.static`
- `framework.static`
- `tool`
- `tv-app-extension`
- `watchkit-extension`
- `watchkit2-extension`
- `xcode-extension`
- `driver-extension`
- `system-extension`
- `xpc-service`
- ``""`` (used for legacy targets)
```
- The command-line tool type string is **`tool`**. The system extension type string is **`system-extension`**, and the DriverKit type string is `driver-extension`.
- XcodeProj's enum confirms these strings. The XcodeGen type is the raw value with `com.apple.product-type.` stripped: XcodeGen's `XCProjExtensions.swift` has `rawValue.replacingOccurrences(of: "com.apple.product-type.", with: "")`. URL: https://raw.githubusercontent.com/tuist/XcodeProj/main/Sources/XcodeProj/Objects/Targets/PBXProductType.swift (file commit `76f5ae3d31c3`, 2026-08-20; latest XcodeProj release 9.17.5)
```swift
    case commandLineTool = "com.apple.product-type.tool"
    case driverExtension = "com.apple.product-type.driver-extension"
    case systemExtension = "com.apple.product-type.system-extension"
...
        case .systemExtension:
            "systemextension"
        case .driverExtension:
            "dext"
```
- XcodeGen's own test fixture uses an Endpoint Security system extension. URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Tests/Fixtures/TestProject/project.yml
```yaml
  EndpointSecuritySystemExtension:
    platform: macOS
    type: system-extension
    sources:
      - EndpointSecurity Extension
    settings:
      PRODUCT_BUNDLE_IDENTIFIER: com.project.App-macOS.EndpointSecurity
      CODE_SIGN_ENTITLEMENTS: EndpointSecurity Extension/EndpointSecurity.entitlements
    scheme: {}
    dependencies:
      - sdk: libEndpointSecurity.tbd
```
  In the same fixture, the app target `App_macOS` (`type: application`) simply lists `- target: EndpointSecuritySystemExtension` under `dependencies:`.
- The fixture's entitlements file contains `com.apple.developer.endpoint-security.client` = `<true/>`. Its Info.plist contains `NSSystemExtensionUsageDescription` and `CFBundlePackageType` = `$(PRODUCT_BUNDLE_PACKAGE_TYPE)`. (Files: `src-partC/xcodegen-Tests_Fixtures_TestProject_EndpointSecurity_Extension_*`)

### Embedding a system extension: automatic "Embed System Extensions" phase
The doc's list of `copy` → `destination` values does **not** include `systemExtensions`. URL: ProjectSpec.md, "Dependency" section:
```
- **copy** - Copy Files Phase for this dependency. This only applies when `embed` is true. Must be specified as an object with the following fields:
    - [x] **destination**: **String** - Destination of the Copy Files phase. This can be one of the following values:
        - `absolutePath`
        - `productsDirectory`
        - `wrapper`
        - `executables`
        - `resources`
        - `javaResources`
        - `frameworks`
        - `sharedFrameworks`
        - `sharedSupport`
        - `plugins`
    - [ ] **subpath**: **String** - The path inside of the destination to copy the files.
```
The source enum matches that list exactly. URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Sources/ProjectSpec/BuildPhaseSpec.swift
```swift
        public enum Destination: String {
            case absolutePath
            case productsDirectory
            case wrapper
            case executables
            case resources
            case javaResources
            case frameworks
            case sharedFrameworks
            case sharedSupport
            case plugins
```
You don't need a `copy` block, though. A `target:` dependency on a `system-extension` (or `driver-extension`) target is put into an auto-generated "Embed System Extensions" phase. URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Sources/XcodeGenKit/PBXProjGenerator.swift
```swift
                if let copyPhase = dependency.copyPhase {
                    // custom copy takes precedence
                    ...
                } else if dependencyTarget.type.isSystemExtension {
                    // embed system extension
                    systemExtensions.append(embedFile)
...
        if !systemExtensions.isEmpty {
            let copyFilesPhase = addObject(
                // With parameters below the Xcode will show "Destination: System Extensions".
                getPBXCopyFilesBuildPhase(dstSubfolderSpec: .productsDirectory, dstPath: "$(SYSTEM_EXTENSIONS_FOLDER_PATH)", name: "Embed System Extensions", files: systemExtensions)
            )
```
`isSystemExtension` is defined in `Sources/ProjectSpec/XCProjExtensions.swift`:
```swift
    public var isSystemExtension: Bool {
        fileExtension == "dext" || fileExtension == "systemextension"
    }
```
Embed defaults to true when the depending target is an app:
```swift
        if isApp {
            // If target is an app, all dependencies should be embed (unless they're static)
            return true
```
The fixture's generated pbxproj shows the resulting phase. URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Tests/Fixtures/TestProject/Project.xcodeproj/project.pbxproj
```
		DE875E9A37F7CB9C347AEFA0 /* Embed System Extensions */ = {
			isa = PBXCopyFilesBuildPhase;
			buildActionMask = 2147483647;
			dstPath = "$(SYSTEM_EXTENSIONS_FOLDER_PATH)";
			dstSubfolderSpec = 16;
			files = (
				5126CD91C2CB41C9B14B6232 /* DriverKitDriver.dext in Embed System Extensions */,
				F4D77E81B0539EA5F4F141A6 /* EndpointSecuritySystemExtension.systemextension in Embed System Extensions */,
```
`SYSTEM_EXTENSIONS_FOLDER_PATH` is an Xcode build setting. That it resolves to `Contents/Library/SystemExtensions` is UNVERIFIED from Xcode docs, but Apple requires that location (see §9).

### Dependency linking options (verbatim)
```
- [ ] **embed**: **Bool** - Whether to embed the dependency. Defaults to true for application target and false for non application targets.
- [ ] **link**: **Bool** - Whether to link the dependency. Defaults to `true` depending on the type of the dependency and the type of the target (e.g. static libraries will only link to executables by default).
- [ ] **codeSign**: **Bool** - Whether the `codeSignOnCopy` setting is applied when embedding framework. Defaults to true.
```
**The doc and the code disagree on the `codeSign` default.** The code is `codeSign: dependency.codeSign ?? !dependencyTarget.type.isExecutable` (PBXProjGenerator.swift). `isExecutable` includes `isSystemExtension`, so an embedded system extension gets **no** `CodeSignOnCopy` by default. The fixture's pbxproj shows `settings = {ATTRIBUTES = (RemoveHeadersOnCopy, ); }` on `EndpointSecuritySystemExtension.systemextension in Embed System Extensions`.

### Local Swift packages and `package:` / `product:` dependencies (verbatim)
```
### Local Package

- [x] **path**: **String** - the path to the package in local. The path must be directory with a `Package.swift`.
- [ ] **group** : **String**- Optional path that specifies the location where the package will live in your xcode project. Use `""` to specify the project root.
- [ ] **excludeFromProject** : **String**- Optional flag to exclude the package from the generated project (useful if the package is already added via xcworkspace and the project is not intended for standalone use), defaults to `false`
```
```
- `package: name` - links to a Swift Package. The name must match the name of a package defined in the top level `packages`
...
**Package dependency**
- [ ] **product**: **String** - The product to use from the package. This defaults to the package name, so is only required if a Package has multiple libraries or a library with a differing name. Use this over `products` when you want to define different linking options per product.
- [ ] **products**: **String** - A list of products to use from the package. This can be used when depending on multiple products from a package.
```
```yaml
packages:
  FooFeature:
    path: Packages/FooFeature
targets:
  App:
    dependencies:
      - package: FooFeature
        products:
          - FooDomain
          - FooUI
```
```yaml
      - package: SwiftPM
        product: SPMUtility
```

### `entitlements` and `info` (both are of type Plist)
```
- [ ] **info**: **[Plist](#plist)** - If defined, this will generate and write an `Info.plist` to the specified path and use it by setting the `INFOPLIST_FILE` build setting for every configuration, unless `INFOPLIST_FILE` is already defined in  **settings** for this configuration. The following properties are generated automatically if appropriate, the rest will have to be provided.
  - `CFBundleIdentifier`
  - `CFBundleInfoDictionaryVersion`
  - `CFBundleExecutable` **Not generated for targets of type bundle**
  - `CFBundleName`
  - `CFBundleDevelopmentRegion`
  - `CFBundleShortVersionString`
  - `CFBundleVersion`
  - `CFBundlePackageType`
- [ ] **entitlements**: **[Plist](#plist)** - If defined this will generate and write a `.entitlements` file, and use it by setting `CODE_SIGN_ENTITLEMENTS` build setting for every configuration. All properties must be provided
```
```
### Plist
Plists are created on disk on every generation of the project. They can be used as a way to define `Info.plist` or `.entitlement` files. Some `Info.plist` properties are generated automatically.

- [x] **path**: **String** - This is the path where the plist will be written to
- [x] **properties**: **[String: Any]** - This is a map of all the plist keys and values
```
```yml
targets:
  App:
    info:
      path: App/Info.plist
      properties:
        UISupportedInterfaceOrientations: [UIInterfaceOrientationPortrait]
        UILaunchStoryboardName: LaunchScreen
    entitlements:
      path: App/App.entitlements
      properties:
        com.apple.security.application-groups: group.com.app
```
**Gotcha:** XcodeGen does not auto-generate `CFBundlePackageType` for `system-extension` targets. `InfoPlistGenerator.swift` only sets it for unit/UI tests (`BNDL`), `application`/`watch2App` (`APPL`), `framework` (`FMWK`), `bundle` (`BNDL`), and `xpcService`/`appExtension` (`XPC!`); everything else hits `default: break`. Set it yourself. The fixture uses `$(PRODUCT_BUNDLE_PACKAGE_TYPE)`; the third-party spec below uses `SYSX`. URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Sources/XcodeGenKit/InfoPlistGenerator.swift

XcodeGen has no `SettingPresets/Products/system-extension.yml`. The directory only contains `app-extension.intents-service.yml app-extension.messages.yml app-extension.yml bundle.ui-testing.yml bundle.unit-test.yml framework.static.yml framework.yml library.static.yml tv-app-extension.yml watchkit2-extension.yml`.

### `settings` (verbatim)
```
- [ ] **groups**: **[String]** - List of [Setting Groups](#setting-groups) to include and merge
- [ ] **configs**: **[String:[Settings](#settings)]** - Mapping of config name to a settings spec. These settings will only be applied for that config. Each key will be matched to any configs that contain the key and is case insensitive. ...
- [ ] **base**: **[String:String]** - Used to specify default settings that apply to any config
```
> Don't mix simple maps with `groups`, `base` and `configs`.
> If `groups`, `base`, `configs` are used then simple maps is silently ignored.
> Settings are merged in the following order: `groups`, `base`, `configs` (simple maps are ignored).

### Build scripts (verbatim)
```
- [ ] **preBuildScripts**: **[[Build Script](#build-script)]** - Build scripts that run *before* any other build phases
- [ ] **postCompileScripts**: **[[Build Script](#build-script)]** - Build scripts that run after the Compile Sources phase
- [ ] **postBuildScripts**: **[[Build Script](#build-script)]** - Build scripts that run *after* any other build phases
```
Each script can contain `path` or `script` (one is required), `name` (default `Run Script`), `inputFiles`, `outputFiles`, `inputFileLists`, `outputFileLists`, `shell` (default `/bin/sh`), `showEnvVars` (default `true`), `runOnlyWhenInstalling` (default `false`), `basedOnDependencyAnalysis` (default `true`), and `discoveredDependencyFile`.
> Either a **path** or **script** must be defined, the rest are optional.

### Schemes
Target `scheme` (verbatim excerpt):
> This is a convenience used to automatically generate schemes for a target based on different configs or included tests. If you want more control check out the top level [Scheme](#scheme).
```
- [x] **configVariants**: **[String]** - This generates a scheme for each entry, using configs that contain the name with debug and release variants. ...
- [ ] **testTargets**: ...
- [ ] **gatherCoverageData**: **Bool** ...
- [ ] **buildArchitectures**: **String** - ... Supported values are `matchRunDestination`, `universal`, and `useTargetSettings`. By default this is `matchRunDestination` if not set.
- [ ] **commandLineArguments**: **[String:Bool]** ...
- [ ] **environmentVariables**: ...
- [ ] **preActions** / **postActions** ...
```
(In practice `configVariants` is not required: the fixture and the real-world spec both use `scheme: {}`.)

Top-level `schemes` (verbatim):
```
- [x] ***build***: Build options
- [ ] ***run***: The run action
- [ ] ***test***: The test action
- [ ] ***profile***: The profile action
- [ ] ***analyze***: The analyze action
- [ ] ***archive***: The archive action
- [ ] ***management***: management metadata
```
```
- [x] **targets**: **[String:String]** or **[String:[String]]** - A map of target names to build and which build types they should be enabled for. The build types can be `all`, `none`, or an array of the following types:
	- `run` or `running`
	- `test` or `testing`
	- `profile` or `profiling`
	- `analyze` or `analyzing`
	- `archive` or `archiving`
```
Common action option: `config` — "If a config, or the build action itself, is not defined the first configuration found of a certain type will be used ... `debug`: run, test, analyze ... `release`: profile, archive".

### Options (verbatim)
```
- [ ] **bundleIdPrefix**: **String** - If this is specified then any target that doesn't have an `PRODUCT_BUNDLE_IDENTIFIER` (via all levels of build settings) will get an autogenerated one by combining `bundleIdPrefix` and the target name: `bundleIdPrefix.name`. The target name will be stripped of all characters that aren't alphanumerics, hyphens, or periods. Underscores will be replaced with hyphens.
- [ ] **deploymentTarget**: **[[Platform](#platform): String]** - A project wide deployment target can be specified for each platform otherwise the default SDK version in Xcode will be used. This will be overridden by any custom build settings that set the deployment target eg `IPHONEOS_DEPLOYMENT_TARGET`. Target specific deployment targets can also be set with [Target](#target).deploymentTarget.
- [ ] **minimumXcodeGenVersion**: **String** - The minimum version of XcodeGen required.
- [ ] **projectFormat**: **String** - The version of Xcode project. By default this is set to `xcode16_0`
```
```yaml
options:
  deploymentTarget:
    watchOS: "2.0"
    tvOS: "10.0"
```
CLI usage (README.md): `xcodegen generate`; "**--spec**: An optional path to a `.yml` or `.json` project spec. Defaults to `project.yml`."

### Real-world reference: third-party XcodeGen spec with an ES system extension (not authoritative)
GenseeAI/gensee-crate `macos/GenseeCrate/project.yml`, commit `2471d6df4d15` (2026-09-07). URL: https://github.com/GenseeAI/gensee-crate/blob/2471d6df4d150f14beedf7807bab6a6fd129884d/macos/GenseeCrate/project.yml (saved: `web/gh-GenseeAI_gensee-crate-project.yml`)
```yaml
    entitlements:
      path: Host/GenseeCrate.entitlements
      properties:
        com.apple.developer.system-extension.install: true
...
    dependencies:
      - target: GenseeCrateEndpointSecurity
      - sdk: SystemExtensions.framework
...
  GenseeCrateEndpointSecurity:
    type: system-extension
    platform: macOS
    info:
      path: EndpointSecurityExtension/Info.plist
      properties:
        CFBundlePackageType: SYSX
        NSEndpointSecurityMachServiceName: "$(TeamIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER).xpc"
        NSSystemExtensionUsageDescription: Gensee Crate monitors process and file activity to protect AI agent sessions.
    entitlements:
      path: EndpointSecurityExtension/GenseeCrateEndpointSecurity.entitlements
      properties:
        com.apple.developer.endpoint-security.client: true
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: ai.gensee.crate.endpoint-security
        PRODUCT_NAME: "$(PRODUCT_BUNDLE_IDENTIFIER)"
        SKIP_INSTALL: YES
    dependencies:
      - sdk: libEndpointSecurity.tbd
      - sdk: libbsm.tbd
```
(`PRODUCT_NAME: "$(PRODUCT_BUNDLE_IDENTIFIER)"` satisfies Apple's rule that the extension's filename must match its bundle identifier; see §9.)

---

## 9. Apple SystemExtensions / Endpoint Security

All Apple pages come from `https://developer.apple.com/tutorials/data/documentation/<path>.json`. Literal `(`, `)` and `:` in the path worked; no encoding was needed. Swift declarations below are copied from each page's `primaryContentSections.declarations.tokens`. Availability comes from `metadata.platforms[].introducedAt`.

### OSSystemExtensionRequest — macOS 10.15
URL: .../systemextensions/ossystemextensionrequest.json — `class OSSystemExtensionRequest`, abstract: "A request to activate or deactivate a system extension."

- `activationRequest(forExtensionWithIdentifier:queue:)`, macOS 10.15. URL: .../systemextensions/ossystemextensionrequest/activationrequest(forextensionwithidentifier:queue:).json
  ```swift
  class func activationRequest(forExtensionWithIdentifier identifier: String, queue: dispatch_queue_t) -> Self
  ```
  Parameters: "identifier: The bundle identifier of the target extension." "queue: The dispatch queue to use when calling delegate methods."
  > Create and submit an activation request whenever you want to use a given extension. If the extension is inactive, the system may need to prompt the user for approval. The request succeeds only after the user gives their approval.
  > If the extension is already active, the request succeeds in short order, without significant delay or user interaction. If you request activation of a new version of an already-active extension, the system prompts the user to resolve the conflict before proceeding.
  > An activation request may succeed, but also indicate that the extension requires a restart to become active. ...
- `deactivationRequest(forExtensionWithIdentifier:queue:)`, macOS 10.15. URL: .../ossystemextensionrequest/deactivationrequest(forextensionwithidentifier:queue:).json
  ```swift
  class func deactivationRequest(forExtensionWithIdentifier identifier: String, queue: dispatch_queue_t) -> Self
  ```
  > The system discovers existing system extensions in the `Contents/Library/SystemExtensions` directory of the main app bundle.
  > A deactivation request may require a restart before deactivating the extension. If the request succeeds but requires a restart to complete, the extension may still appear operational until the next restart.
- `propertiesRequest(forExtensionWithIdentifier:queue:)`, **macOS 12.0**: `class func propertiesRequest(forExtensionWithIdentifier identifier: String, queue: dispatch_queue_t) -> Self`
- `var delegate: (any OSSystemExtensionRequestDelegate)?` and `var identifier: String`
- `OSSystemExtensionRequest.Result`: `case completed` ("The request completed successfully.") and `case willCompleteAfterReboot` ("The request requires a restart to complete successfully.")
- `OSSystemExtensionRequest.ReplacementAction`: `case cancel` and `case replace`

### OSSystemExtensionManager — macOS 10.15
URL: .../systemextensions/ossystemextensionmanager.json
```swift
class var shared: OSSystemExtensionManager { get }
func submitRequest(_ request: OSSystemExtensionRequest)
```
> Create an instance of OSSystemExtensionRequest with the class methods on that type, and submit it to the shared instance of the extension manager with submitRequest(_:). Set the delegate on the request to receive the result of the activation or deactivation. The delegate also receives notifications if the user needs to authorize the extension or if a version conflict occurs.

### OSSystemExtensionRequestDelegate — macOS 10.15; `protocol OSSystemExtensionRequestDelegate : NSObjectProtocol`
URL: .../systemextensions/ossystemextensionrequestdelegate.json and each method page:
```swift
func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction   // macOS 10.15
func requestNeedsUserApproval(_ request: OSSystemExtensionRequest)                                                       // macOS 10.15
func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result)            // macOS 10.15
func request(_ request: OSSystemExtensionRequest, didFailWithError error: any Error)                                      // macOS 10.15
optional func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties])     // macOS 12.0
```
Which methods are required vs. optional is confirmed by the SDK header (MacOSX26.5.sdk `SystemExtensions.framework/Versions/A/Headers/SystemExtensions.h`, via the GitHub mirror `alexey-lysiuk/macos-sdk` at commit `896cd40df984`, file `src-partC/sdk26.5-SystemExtensions.h`). The protocol begins with `@required`, which covers the four 10.15 methods. `@optional` comes before `request:foundProperties:` only.

Discussion quotes:
- actionForReplacingExtension:
  > The manager calls this method when it encounters an existing extension with the same team and bundle identifiers, but with different version identifiers. It uses the CFBundleVersion and CFBundleShortVersionString identifiers to determine if the existing and new versions differ. ... If you return OSSystemExtensionRequest.ReplacementAction.cancel, the manager aborts the installation and calls request(_:didFailWithError:), with the OSSystemExtensionError.Code.requestCanceled error code.
  > If the local system has System Extension developer mode enabled, the manager always calls this method when it finds an existing installation, even if the version identifiers match.
- requestNeedsUserApproval:
  > Activating an extension may require explicit user approval to proceed. ... Activation remains pending until the user grants or denies permission, or until the app quits.
- didFinishWithResult:
  > If the request completes with the OSSystemExtensionRequest.Result.willCompleteAfterReboot result, then the extension isn't active until after the next restart. After restarting, the most recently-processed request determines the extension's state.

### "Installing System Extensions and Drivers" article
URL: .../systemextensions/installing-system-extensions-and-drivers.json
> System extensions reside inside your app's `Contents/Library/SystemExtensions` folder.

> During the activation process, the system verifies:
> - Your extension is installed in the `Contents/Library/SystemExtensions` folder of your app.
> - Your app is installed in an appropriate `Applications` directory of the system.
> - The code signature of your extension.
> - The entitlements in the code signature match the entitlements granted to your development team.
> - The identifer in your activation request matches the one in your system extension bundle.
> - The identifier isn't already in use by another system extension.

> The system automatically uninstalls any system extensions when the user deletes the corresponding app. You can also uninstall a system extension by creating a deactivation request.

> To see the system extensions installed on your system, run the `systemextensionsctl` command-line tool with the `list` option from Terminal.
> `% systemextensionsctl list`

The article's sample code:
```swift
let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: driverID,
                     queue: DispatchQueue.main)
request.delegate = self
let extensionManager = OSSystemExtensionManager.shared
extensionManager.submitRequest(request)
```

### SystemExtensions framework landing page: naming, Team ID, and notarization rules
URL: .../systemextensions.json
> To successfully activate your extension, you must adhere to the following rules:
> - The extension must match your bundle identifier, excluding file extension. For example, ... a NetworkExtension extension with bundle identifier `com.example.networkextension` must use the filename `com.example.networkextension.systemextension`.
> - You must use the same Team ID when signing the extension that you use for signing your app, unless the extension has the `com.apple.developer.system-extension.redistributable` entitlement.
> - You must either distribute your app and extension through the Mac App Store, or notarize them.

### Requirement that the app be in /Applications
Apple states this in three places:
- The Installing article: "Your app is installed in an appropriate `Applications` directory of the system." (quoted above)
- `OSSystemExtensionError.Code.unsupportedParentBundleLocation` (raw value 3). URL: .../systemextensions/ossystemextensionerror/code/unsupportedparentbundlelocation.json
  > An error code that indicates the extension's parent app isn't in a valid location for activation.
  > The expected location of a driver extension is in the `Contents/Library/SystemExtensions` directory of a macOS app. The app itself must be in one of the system's `Applications` directories.
- "Debugging and testing system extensions". URL: .../driverkit/debugging-and-testing-system-extensions.json
  > You must place all system extensions in the `Contents/Library/SystemExtensions` directory of your app bundle, and the app itself must be installed in one of the system's `Applications` directories. To allow development of your app outside of these directories, use the `systemextensionsctl` command-line tool to enable developer mode. When in developer mode, the system doesn't check the location of your system extension prior to loading it, so you can load it from anywhere in the file system. To enable developer mode, open a Terminal window and execute the following command:
  > `% systemextensionsctl developer on`
  > To turn developer mode off, open Terminal and run the same tool with `developer off` as the parameter.

  > ### Disable code-signing and notarization checks
  > System Integrity Protection (SIP) in macOS prevents unauthorized code from running on your system. Xcode doesn't notarize apps or system extensions during the normal development cycle, so disabling SIP bypasses the notarization checks that the system normally performs, and allows you to debug your code more quickly.

### OSSystemExtensionError.Code — all cases are macOS 10.15 (iOS/iPadOS/Mac Catalyst 18.4)
URL: .../systemextensions/ossystemextensionerror/code.json. Integer values come from the SDK header (sdk26.5 `SystemExtensions.h` lines 49-61).
| Swift case | ObjC constant = value | Apple abstract |
|---|---|---|
| unknown | OSSystemExtensionErrorUnknown = 1 | An error code that indicates an unknown error occurred. |
| missingEntitlement | ...MissingEntitlement = 2 | ...the system extension lacks a required entitlement. (Discussion: "The app must have the System Extension Entitlement to activate or deactivate system extensions.") |
| unsupportedParentBundleLocation | ...UnsupportedParentBundleLocation = 3 | ...the extension's parent app isn't in a valid location for activation. |
| extensionNotFound | ...ExtensionNotFound = 4 | ...the manager can't find the system extension. |
| extensionMissingIdentifier | ...ExtensionMissingIdentifier = 5 | ...the extension identifier is missing. |
| duplicateExtensionIdentifer (sic) | ...DuplicateExtensionIdentifer = 6 | ...the extension identifier duplicates an existing identifier. |
| unknownExtensionCategory | ...UnknownExtensionCategory = 7 | ...can't recognize the extension's category identifier. |
| codeSignatureInvalid | ...CodeSignatureInvalid = 8 | ...the extension's signature is invalid. |
| validationFailed | ...ValidationFailed = 9 | ...the manager can't validate the extension. |
| forbiddenBySystemPolicy | ...ForbiddenBySystemPolicy = 10 | ...the system policy prohibits activating the system extension. |
| requestCanceled | ...RequestCanceled = 11 | ...the system extension manager request was canceled. |
| requestSuperseded | ...RequestSuperseded = 12 | ...failed because the system already has a pending request for the same identifier. |
| authorizationRequired | ...AuthorizationRequired = 13 | ...the system was unable to obtain the proper authorization. |

### Entitlements
- **`com.apple.developer.system-extension.install`** — "System Extension Entitlement", macOS 10.15. `details.value` = `{"baseType": "boolean"}`. URL: .../bundleresources/entitlements/com.apple.developer.system-extension.install.json
  > A Boolean value that indicates whether your app has permission to activate or deactivate system extensions.
  > To add this entitlement to your app, enable the System Extension capability in Xcode. Add this entitlement for all system extension types, including DriverKit extensions.

  The value is a Boolean `true`. Apple does not document a string value such as "systemextension-install".
- **`com.apple.developer.endpoint-security.client`** — macOS 10.15, boolean. URL: .../bundleresources/entitlements/com.apple.developer.endpoint-security.client.json
  > The entitlement required to monitor system events for potentially malicious activity.
  > You must request this entitlement from Apple. For information about how to request the entitlement, see System Extensions and DriverKit.
  > If your app or extension lacks this requirement, es_new_client(_:_:) fails with the result ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED.
- **`com.apple.developer.system-extension.redistributable`** — boolean:
  > This extension allows a distributing app to have a different team ID than the one associated with the system extension. If this entitlement isn't present, the team ID of the app and system extension must match.
- `es_new_client(_:_:)`, macOS 10.15. URL: .../endpointsecurity/es_new_client(_:_:).json
  ```swift
  func es_new_client(_ client: UnsafeMutablePointer<OpaquePointer?>, _ handler: @escaping es_handler_block_t) -> es_new_client_result_t
  ```
  > To create a client, your app must have the `com.apple.developer.endpoint-security.client` entitlement. The user also needs to approve your app with Transparency, Consent, and Control (TCC) mechanisms. The user does this in the Security and Privacy pane of System Preferences, by adding the app to Full Disk Access.

  Result codes:
  - `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`: "The caller isn't properly entitled to connect to Endpoint Security."
  - `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`: "The caller isn't permitted to connect to Endpoint Security." / "This error indicates the app lacks Transparency, Consent, and Control (TCC) approval from the user."
  - `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`: "The caller isn't running as root."

### Info.plist keys
- **NSSystemExtensionUsageDescriptionKey**. URL: .../systemextensions/nssystemextensionusagedescriptionkey.json
  > A message that tells the user why the app is trying to install a system extension bundle.
  > This key is required for all system extensions except DriverKit extensions, and must be in the extension's `Info.plist` file. Failure to include this key results in an error at activation time.

  The literal plist key string `NSSystemExtensionUsageDescription` comes from XcodeGen's fixture and the third-party spec. Apple's page only names the constant.
- **NSEndpointSecurityMachServiceName**. Apple's DocC has **no** page for it: `.../bundleresources/information-property-list/nsendpointsecuritymachservicename.json` returns 404, and it isn't listed in `endpointsecurity.json` or `information-property-list.json`. Apple documents it in the **EndpointSecurity(7) man page** shipped in the SDK (`MacOSX26.5.sdk/usr/share/man/man7/EndpointSecurity.7`, via the mirror; file `src-partC/man/sdk26.5-EndpointSecurity.7`):
  ```
  If the ES client is a system extension, the following optional keys can be set in the bundle's Info.plist:
  ...
  .It Ar NSEndpointSecurityMachServiceName
  Type: String
  .Pp
  If set, this string will be the name of the MachService which can be used for XPC between the ES extension and its app.
  If not set, a default mach service (name: <teamID>.<bundleID>.xpc) will be provided but its usage is deprecated.
  ```
  The same man page also documents `NSEndpointSecurityEarlyBoot` (Boolean) and `NSEndpointSecurityRebootRequired` (Boolean).

  Apple DTS on the forums (WebFetch), https://developer.apple.com/forums/thread/713744 (Sep 2022):
  > Specifically to do this in your ES sysex: 1. Edit its `Info.plist` to list the name in the `NSEndpointSecurityMachServiceName` property. 2. On start, set up a listener for that name using `NSXPCListener`.

  > I recommend that you do the following: * Add your Team ID as a prefix. * Add a suffix to distinguish this from your sysex, so something like `.xpc-qqq`.

  > On the sysex side, call `-[NSXPCListener initWithMachServiceName:]` ... Then, still on the client side call `-[NSXPCConnection initWithMachServiceName:options:]`, passing in the endpoint name and `NSXPCConnectionPrivileged`.

### systemextensionsctl
Man page systemextensionsctl(8), page dated "October 30, 2023". Source: https://keith.github.io/xcode-man-pages/systemextensionsctl.8.html (mirror HEAD `46d6bd5d`, "Xcode 27.2 beta 2 (27B5028f)"). Verbatim:
```
SYNOPSIS
    systemextensionsctl developer [on | off]
    systemextensionsctl list
    systemextensionsctl reset
...
Users should not run systemextensionsctl under most circumstances; this utility is intended for software developers.
  developer [on | off]
  Turn developer mode on and off. When the computer examines a new system extension, it performs a version check to see if it is the same as a system extension that is already installed. When developer mode is on, this version check is skipped.
  list
  List the system extensions and their state. States include:
      activated enabled            Available for use
      activated waiting for user   Waiting for user approval via System Settings
      activated disabled           Available but currently disabled by the user, can be enabled using System Settings
      terminated waiting for uninstall on reboot   Will be removed at the next computer restart
  reset
  Forcibly reset system extensions. This removes all system extensions and clears related state.
```
- **`uninstall` is not in the man page.** It does appear in the tool's own usage output. Third-party captures:
  - https://derflounder.wordpress.com/2020/09/01/uninstalling-macos-system-extensions/ :
    ```
    systemextensionsctl: usage:
    	systemextensionsctl developer [on|off]
    	systemextensionsctl list [category]
    	systemextensionsctl reset  - reset all System Extensions state
    	systemextensionsctl uninstall  ; can also accept '-' for teamID
    ```
  - A newer capture (2025) that also shows `gc`: https://gist.github.com/joshuataylor/bcbb9d8b80c83d3f188195a61ef60e4e
    ```
    systemextensionsctl uninstall <teamID> <bundleID>; teamID can also be '-' (for matching empty Team ID)
    systemextensionsctl gc  - garbage collect orphaned system extension(s)
    ```
- **`uninstall` requires SIP to be disabled.** Several captures of the tool's message agree:
  - graham pugh, 2021: https://grahamrpugh.com/2021/04/06/delete-system-extension-command-line.html
  - verityj, 2023: https://verityj.github.io/2023/06/12/extensions.html
  - Apple DTS, Jan 2025 (WebFetch): https://developer.apple.com/forums/thread/773002
  - GitHub issue on macOS 26, 2026-09-17: https://github.com/daseinlabs/parsec/issues/34

  The message is:
  ```
  At this time, this tool cannot be used if System Integrity Protection is enabled.
  This limitation will be removed in the near future.
  Please remember to re-enable System Integrity Protection!
  ```
  derflounder adds: "Note: As of September 1, 2020, running the systemextensionsctl uninstall command requires System Integrity Protection (SIP) to be disabled."
- **Whether `developer on` requires SIP disabled:** neither Apple's docs nor the man page say so. Third-party sources disagree:
  - Saying SIP is required:
    - dognotdog/ptpwebcam README: "`systemextensionsctl developer on` but for that to work we need to disable SIP as of MacOS 13"
    - obscuravpn-client README lists "Disable system integrity protection" before `systemextensionsctl developer on`
  - Not mentioning SIP: denoland/clawpatrol README uses `sudo systemextensionsctl developer on    # one-time, allows Apple Dev sysexts`
- Apple's System Extensions page (https://developer.apple.com/system-extensions/):
  > If you plan to deploy drivers built with DriverKit, allow other developers to use your system extensions, or use the EndpointSecurity API, you'll need to request an entitlement from Apple.
  > While your request is in review, you can test system extensions on your Mac by temporarily turning off System Integrity Protection.

---

## 10. Notarization (notarytool, stapler) and Developer ID

### "Customizing the notarization workflow"
URL: https://developer.apple.com/tutorials/data/documentation/security/customizing-the-notarization-workflow.json (verbatim code blocks). **Apple's listings have no trailing `\`.** In a shell, either put everything on one line or add backslashes.
```sh
% xcrun notarytool submit OvernightTextEditor_11.6.8.zip
                   --keychain-profile "notarytool-password"
                   --wait
                   --webhook "https://example.com/notarization"
```
```sh
% xcrun notarytool store-credentials "notarytool-password"
               --apple-id "<AppleID>"
               --team-id <DeveloperTeamID>
               --password <secret_2FA_password>
```
```sh
% xcrun notarytool log 2efe2717-52ef-43a5-96dc-0797e4ca1041 --keychain-profile "notarytool-password" developer_log.json
```
```sh
% xcrun stapler staple "Overnight TextEditor.app"
```
```sh
/usr/bin/ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"
```
Apple's text:
> Because you can't upload the `.app` bundle directly to the notary service, you'll need to create a compressed archive containing the app

> The notary service accepts disk images (UDIF format), signed flat installer packages, and ZIP archives.

> Use the `wait` flag to tell `notarytool` to exit only after the Notary service finishes processing the submission.

> You can add the `apple-id` and `password` options to supply your App Store Connect credentials. Because App Store Connect requires two-factor authentication (2FA) on all accounts, you must create an app-specific password for `notarytool`

> While you can notarize a ZIP archive, you can't staple to it directly. Instead, run `stapler` against each item that you added to the archive. Then create a new ZIP file containing the stapled items for distribution.

> The `altool` command has been deprecated, and the Apple notary service no longer supports `altool` from November 1, 2023.

### notarytool(1) man page
Source: https://keith.github.io/xcode-man-pages/notarytool.1.html (page date "April 28th, 2022"). Synopsis (verbatim tokens):
```
notarytool submit file-path { -k key-path -d key-id [-i issuer] | --apple-id apple-id [--password app-specific-password] --team-id team-id | -p profile-name [--keychain keychain-path] } [--wait --no-s3-acceleration --force]
notarytool store-credentials profile-name { -k key-path -d key-id [-i issuer] | --apple-id apple-id [--password app-specific-password] --team-id team-id } [--no-validate] [--keychain keychain-path | --sync]
```
> -p, --keychain-profile profile-name  Authenticate using credentials stored in the Keychain by notarytool. Use the profile name that you previously provided via the store-credentials command.

> [--password app-specific-password] App-specific password for your Apple ID. You will be given a secure prompt on the command line if Apple ID and Team ID are provided but the --password option is not specified.

> store-credentials ... Save authentication credentials for the Apple notary service to the default login keychain. ... --validate, --no-validate ... The default is --validate.

> --wait, --no-wait Rather than exiting after a successful upload, begin waiting for your submission to complete. The default is --no-wait.

Man page examples:
```
notarytool store-credentials MyGreatCompany-ASP --apple-id mygreataccount@example.com --team-id K36BKF7T3D
notarytool submit MyDiskImage.dmg -p MyGreatCompany --wait
notarytool log d0d37a38-dc80-4603-bca9-80705a49cbbd -p MyGreatCompany ~/Desktop/developer_log.json
```
> notarytool submit works only with UDIF disk images, signed "flat" installer packages, and zip files.

The `wait` subcommand returns once the service responds with a status of "Accepted", "Invalid", "Rejected", or if a fatal error occurs.

### stapler(1)
Source: https://keith.github.io/xcode-man-pages/stapler.1.html
```
stapler staple [-q] [-v] path
stapler validate [-q] [-v] path
```
> Stapling does not invalidate the code signature and must be run after an executable or archive has been code-signed and notarized with Developer ID. Code-signing a supported file format invalidates any stapled tickets, so stapler staple must be run again if this occurs.

> stapler works only with UDIF disk images, signed "flat" installer packages, and certain code-signed executable bundles such as ".app".

> stapler requires internet access to retrieve tickets when stapling or validating.

### Developer ID requirements
Source: "Notarizing macOS software before distribution", https://developer.apple.com/tutorials/data/documentation/security/notarizing-macos-software-before-distribution.json
> - Use a "Developer ID" application, kernel extension, system extension, or installer certificate for your code-signing signature. (Don't use a Mac Distribution, ad hoc, Apple Developer, or local development certificate.)
> - Enable the Hardened Runtime capability for your app and command line targets ...
> - Include a secure timestamp with your code-signing signature. ...
> - Don't include the `com.apple.security.get-task-allow` entitlement with the value set to any variation of `true`.

> Beginning in macOS 10.15, all software built after June 1, 2019, and distributed with Developer ID must be notarized.

Source: "Resolving common notarization issues" (…/security/resolving-common-notarization-issues.json):
> When code signing items like Mach-O files, disk images, bundles, apps, command line tools, photos, and so on, sign with a Developer ID Application certificate.

> be sure to add a secure timestamp by adding the `timestamp` option to your `OTHER_CODE_SIGN_FLAGS` build setting, or by using the option directly with the `codesign` utility if you sign manually

> add the following option to the `OTHER_CODE_SIGN_FLAGS` build setting: `--options=runtime`

```sh
% codesign -vvv --deep --strict /path/to/binary/or/bundle
% spctl -vvv --assess --type exec /path/to/application
```

### Provisioning profiles are needed for restricted entitlements under Developer ID
Source: TN3125, https://developer.apple.com/tutorials/data/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles.json
> A macOS app can claim certain entitlements without them being authorized by a provisioning profile. These *unrestricted entitlements* include: `com.apple.security.get-task-allow`, `com.apple.security.application-groups`, Those used to enable and configure the App Sandbox, Those used to configure the Hardened Runtime

> In contrast, *restricted entitlements* must be authorized by a provisioning profile.

> macOS supports provisioning profiles for both App Store and Developer ID distribution. Some entitlements are not supported by Developer ID profiles.

> macOS expects to find the profile at `MyApp.app/Contents/embedded.provisionprofile`.

> In this document the term *app* refers to a main executable packaged in a bundle structure. This encompasses apps, app extensions, App Clips, system extensions, and XPC Services.

> Developer ID profiles, which have an expiration date far in the future.

Source: "Signing a daemon with a restricted entitlement", https://developer.apple.com/tutorials/data/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement.json
> the Endpoint Security API is usable from a daemon but requires that the daemon has the com.apple.developer.endpoint-security.client entitlement, and that it's authorized by a provisioning profile.
> If the API you're using supports system extensions, avoid this issue by switching from a daemon to a system extension. System extensions readily support provisioning profiles, and Xcode automatically creates and embeds the profile in that case.

The same page also says: "follow the instructions on Provisioning with managed capabilities to add the Endpoint Security additional capability to your App ID."

Source: Apple Developer Account Help, "Supported capabilities (macOS)", https://developer.apple.com/help/account/reference/supported-capabilities-macos. Table columns are ADP | Developer ID | Apple Developer:
```
System Extension   | ✓ | ✓ | (none)
Network extensions | ✓ | ✓ | (none)
Hardened runtime   | ✓ | ✓ | ✓
App groups         | ✓ | ✓ | ✓
```
Endpoint Security is **not** listed in that table. It is a managed or additional capability that needs Apple approval: "Managed capabilities require approval from Apple to use." (https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities)

Contrast with Network Extension: Developer ID uses suffixed entitlement values ("…when signed with a Developer ID profile"), such as `content-filter-provider-systemextension`, `packet-tunnel-provider-systemextension`, `app-proxy-provider-systemextension` and `dns-proxy-systemextension`. (…/bundleresources/entitlements/com.apple.developer.networking.networkextension.json) Apple's docs show no such suffix for ES or system-extension.install; both are plain booleans.

---

## 11. NSXPCConnection and NSXPCListener

URLs are under `https://developer.apple.com/tutorials/data/documentation/foundation/...` (literal parentheses and colons worked).

| API | Swift declaration (verbatim) | macOS introducedAt |
|---|---|---|
| NSXPCConnection.setCodeSigningRequirement(_:) | `func setCodeSigningRequirement(_ requirement: String)` | **13.0** (macOS only) |
| NSXPCListener.setConnectionCodeSigningRequirement(_:) | `func setConnectionCodeSigningRequirement(_ requirement: String)` | **13.0** (macOS only) |
| NSXPCConnection.init(machServiceName:options:) | `init(machServiceName name: String, options: NSXPCConnection.Options = [])` | 10.8 |
| NSXPCConnection.Options.privileged | `static var privileged: NSXPCConnection.Options { get }` | 10.8 (iOS 6.0, Mac Catalyst 13.1, tvOS 9.0, visionOS 1.0, watchOS 2.0) |
| NSXPCListener.init(machServiceName:) | `init(machServiceName name: String)` | 10.8 |

The SDK header (`sdk26.5-NSXPCConnection.h`) confirms:
```objc
- (void)setCodeSigningRequirement:(NSString *)requirement API_AVAILABLE(macos(13.0)) API_UNAVAILABLE(ios, tvos, watchos);
- (void)setConnectionCodeSigningRequirement:(NSString *)requirement API_AVAILABLE(macos(13.0)) API_UNAVAILABLE(ios, tvos, watchos);
    NSXPCConnectionPrivileged = (1 << 12UL)
```
Doc text:
- setCodeSigningRequirement:
  > Use this method to enforce a code-signing requirement on the peer process of an XPC connection. ... Calling this method with a malformed `requirement` results in a fatal error in Swift, or throws an exception in Objective-C. If new messages don't match the requirement, the connection becomes invalidated.
  > Call this method before calling resume(), since it's an XPC error to call this method more than once.

  Example: `c.setCodeSigningRequirement("entitlement [com.example.testentitlement] exists")`
- setConnectionCodeSigningRequirement (from the header comment):
  > Sets the code signing requirement for new connections. If the requirement is malformed, an exception is thrown. If new peer connections do not match the requirement, the incoming connection is automatically rejected before consulting the delegate.
  > This method will only work on `anonymousListener` or `initWithMachServiceName` listener instances. Use on other types of listeners will result in an assertion failure.
- init(machServiceName:options:):
  > If the connection is being made to a process that is running in a privileged Mach bootstrap context (for example, a daemon started by a `launchd` property list in `/Library/LaunchDaemons`), then pass the NSXPCConnection option.

  The doc's link text is truncated in the JSON. The header says "use the NSXPCConnectionPrivileged option".
- Options.privileged:
  > Use this option if connecting to a service in the privileged Mach bootstrap (for example, a daemon with a `launchd.plist` in `/Library/LaunchDaemons)`.
- NSXPCListener `delegate` is `@property (nullable, weak) id <NSXPCListenerDelegate> delegate;` (header). It is weak, so keep a strong reference to the delegate. The forum thread above shows this exact bug.

---

## 12. Full Disk Access deep link

**Primary Apple source:** the Endpoint Security SDK header `EndpointSecurity/ESClient.h`. The text is identical in MacOSX13.3, 14.5, 15.5 and 26.5 SDKs (files `src-partC/sdk{13.3,14.5,15.5,26.5}-ESClient.h`, from the GitHub mirror alexey-lysiuk/macos-sdk at commit `896cd40df984`):
```
 * @note The only supported way to check if an application is properly TCC authorized for Full Disk Access
 *       is to call es_new_client and handling ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED in a way appropriate
 *       to your application.  Most applications will want to ask the user for TCC authorization when
 *       es_new_client returns ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED.
 *       To direct the user to the Full Disk Access section in System Settings, applications can use the following URLs:
 *       `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles` (macOS 13 and later)
 *       `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles` (until macOS 12)
 *       Applications are advised to use the new URL in macOS 13 as the old one may stop working in a future release.
```
- **Apple-recommended on macOS 13+:** `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles`
- **Legacy, officially "until macOS 12":** `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`. Apple warns it "may stop working in a future release".

Third-party sources:
- bvanpeski/SystemPreferences, `macos_preferencepanes-Ventura.md`, "How to open every macOS System Settings Section (macOS 13+)", "as of macOS Sonoma 14.2" (commit `f291dc30`, 2024-01-27). URL: https://github.com/bvanpeski/SystemPreferences/blob/main/macos_preferencepanes-Ventura.md
  > * **Full Disk Access:** `open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"`

  and, for the primary pane, `open x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension` vs `open x-apple.systempreferences:com.apple.preference.security` (legacy).
  > macOS Ventura and newer operating systems use a new extension framework but still support some older prefpane calls. Who knows how long those will continue to work

- derflounder, 2022-10-25, Ventura. Lists both `com.apple.preference.security` and `com.apple.settings.PrivacySecurity.extension` for "Open Privacy & Security". It has no FDA anchor. https://derflounder.wordpress.com/2022/10/25/opening-macos-venturas-system-settings-to-desired-locations-via-the-command-line/
- Code in actively maintained projects. Dates are the last commit touching the file.
  - Using the **legacy** URL:
    - objective-see/BlockBlock (2026-04-13)
    - Brandon7CC/mac-monitor ESManager.swift (2025-09-30; opened on `.notPermitted`)
    - IBM/mac-ibm-migration-tool (2026-03-16)
    - mactools-app/MacTools (2026-08-29)
    - canyonroad/agentsh (2026-04-03; it also uses `...?Privacy_EndpointSecurity` for the ES extensions pane)
    - tmc/macgo (2026-02-17, with fallback)
    - eddmann/ClaudeMeter (2026-05-19, with fallback)
  - Using the **new** URL:
    - objective-see/AuRevoir (2026-04-09). Uses `if (@available(macOS 13.0, *))` → new URL, else legacy.
    - HarfangLab/endpoint-sec Rust crate (2026-03-30). Mirrors the ESClient.h note.
    - strongdm/leash (2025-10-21)
  - Trying the new URL first, then legacy: lobehub (2026-08-01), xopcai (2026-05-25), viticci/remctl (2026-09-04)
  - sweetrb/apple-notes-mcp TECHNICAL_NOTES.md (2026-10-03):
    > Apple documents the Full Disk Access URL in `EndpointSecurity/ESClient.h` ... (checked on macOS 27.2, 2026-09-24)

    This is about related anchors, not FDA specifically.

---

## UNVERIFIED (could not confirm from a fetched primary source)
1. Whether `systemextensionsctl developer on` itself requires SIP to be disabled (on any macOS version). Apple docs and the man page don't say so. Third-party READMEs conflict.
2. That `systemextensionsctl uninstall` still requires SIP disabled on the *latest* macOS. Third-party evidence goes up to macOS 26 (GitHub issue, 2026-09-17), but there is no Apple documentation. The man page doesn't document `uninstall` (or `gc`) at all.
3. That the legacy URL `com.apple.preference.security?Privacy_AllFiles` still works on macOS 14, 15, 26 or 27. Apple only says "until macOS 12" and warns it may stop working. Third-party code still uses it and I found no report of breakage, but nothing confirms it directly. The new `com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles` is Apple-documented for "macOS 13 and later" in SDK headers up to 26.5. Actual behaviour on 15, 26 and 27 was not tested.
4. The exact value of the Xcode build setting `SYSTEM_EXTENSIONS_FOLDER_PATH` (presumably `$(CONTENTS_FOLDER_PATH)/Library/SystemExtensions`). Not found in a fetched Apple doc.
5. `CFBundlePackageType` = `SYSX` for system extensions. Seen only in a third-party spec, not in an Apple doc.
6. The raw string value of the `NSSystemExtensionUsageDescriptionKey` constant (`NSSystemExtensionUsageDescription`). Seen only in XcodeGen's fixture and the third-party spec.
7. Forum quotes (threads 713744 and 773002) are WebFetch model extractions, not byte-exact. curl was blocked by Apple's human-verification redirect.
8. Whether Developer ID provisioning profiles actually support the Endpoint Security managed capability. TN3125 says "Some entitlements are not supported by Developer ID profiles". The macOS capability table lists System Extension as Developer ID-supported but doesn't list Endpoint Security. Real-world Developer ID-distributed ES products imply it works (e.g. objective-see TaskExplorer README: "The extension's Endpoint Security entitlement requires a provisioning profile"), but no Apple page states it.
