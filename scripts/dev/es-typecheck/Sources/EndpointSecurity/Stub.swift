// Stub of the EndpointSecurity Swift interface for type-checking on Linux. Shapes follow the
// DocC Swift declarations: C enums import as RawRepresentable structs, es_client_t * as
// OpaquePointer, unions as structs with all members. Never linked into a product.
#if canImport(Glibc)
import Glibc

// MARK: Darwin bits the native source uses
public typealias integer_t = Int32
public typealias natural_t = UInt32
public typealias mach_msg_type_number_t = natural_t
public typealias task_flavor_t = natural_t
public typealias mach_port_t = UInt32
public var TASK_AUDIT_TOKEN: Int32 { 15 }
public var mach_task_self_: mach_port_t { 0 }
public func task_info(_ t: mach_port_t, _ f: task_flavor_t, _ out: UnsafeMutablePointer<integer_t>!, _ cnt: UnsafeMutablePointer<mach_msg_type_number_t>!) -> Int32 { 0 }
public struct mach_timebase_info_data_t { public var numer: UInt32 = 1; public var denom: UInt32 = 1; public init() {} }
public func mach_timebase_info(_ i: UnsafeMutablePointer<mach_timebase_info_data_t>!) -> Int32 { 0 }
public func mach_absolute_time() -> UInt64 { 0 }
public struct audit_token_t { public var val: (UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32) = (0, 0, 0, 0, 0, 0, 0, 0); public init() {} }
public func audit_token_to_pid(_ t: audit_token_t) -> pid_t { 0 }
public func audit_token_to_pidversion(_ t: audit_token_t) -> Int32 { 0 }
public func audit_token_to_euid(_ t: audit_token_t) -> uid_t { 0 }

// MARK: Types
public struct es_string_token_t { public var length: Int; public var data: UnsafePointer<CChar>! }
public struct es_token_t { public var size: Int; public var data: UnsafePointer<UInt8>! }
public struct es_file_t { public var path: es_string_token_t; public var path_truncated: Bool; public var stat: stat }
public typealias es_cdhash_t = (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                                UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
public struct es_process_t {
    public var audit_token: audit_token_t
    public var ppid: pid_t
    public var original_ppid: pid_t
    public var group_id: pid_t
    public var session_id: pid_t
    public var codesigning_flags: UInt32
    public var is_platform_binary: Bool
    public var is_es_client: Bool
    public var cdhash: es_cdhash_t
    public var signing_id: es_string_token_t
    public var team_id: es_string_token_t
    public var executable: UnsafeMutablePointer<es_file_t>
    public var tty: UnsafeMutablePointer<es_file_t>?
    public var start_time: timeval
    public var responsible_audit_token: audit_token_t
    public var parent_audit_token: audit_token_t
}
public struct es_thread_t { public var thread_id: UInt64 }

// Case names are verified (docs/research/endpoint-security-api.md §12); raw values are not, and the
// code never depends on them (they only appear in log lines).
public struct es_event_type_t: Equatable, Hashable, RawRepresentable, Sendable {
    public var rawValue: UInt32
    public init(_ v: UInt32) { rawValue = v }
    public init(rawValue: UInt32) { self.rawValue = rawValue }
}
public var ES_EVENT_TYPE_AUTH_EXEC: es_event_type_t { .init(0) }
public var ES_EVENT_TYPE_AUTH_OPEN: es_event_type_t { .init(1) }
public var ES_EVENT_TYPE_AUTH_RENAME: es_event_type_t { .init(6) }
public var ES_EVENT_TYPE_AUTH_UNLINK: es_event_type_t { .init(8) }
public var ES_EVENT_TYPE_NOTIFY_EXEC: es_event_type_t { .init(9) }
public var ES_EVENT_TYPE_NOTIFY_OPEN: es_event_type_t { .init(10) }
public var ES_EVENT_TYPE_NOTIFY_FORK: es_event_type_t { .init(11) }
public var ES_EVENT_TYPE_NOTIFY_CLOSE: es_event_type_t { .init(12) }
public var ES_EVENT_TYPE_NOTIFY_CREATE: es_event_type_t { .init(13) }
public var ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: es_event_type_t { .init(14) }
public var ES_EVENT_TYPE_NOTIFY_EXIT: es_event_type_t { .init(15) }
public var ES_EVENT_TYPE_NOTIFY_LINK: es_event_type_t { .init(19) }
public var ES_EVENT_TYPE_NOTIFY_RENAME: es_event_type_t { .init(25) }
public var ES_EVENT_TYPE_NOTIFY_UNLINK: es_event_type_t { .init(32) }
public var ES_EVENT_TYPE_AUTH_LINK: es_event_type_t { .init(42) }
public var ES_EVENT_TYPE_AUTH_CREATE: es_event_type_t { .init(44) }
public var ES_EVENT_TYPE_NOTIFY_TRUNCATE: es_event_type_t { .init(41) }
public var ES_EVENT_TYPE_AUTH_TRUNCATE: es_event_type_t { .init(50) }
public var ES_EVENT_TYPE_AUTH_CLONE: es_event_type_t { .init(60) }
public var ES_EVENT_TYPE_NOTIFY_CLONE: es_event_type_t { .init(61) }
public var ES_EVENT_TYPE_AUTH_READDIR: es_event_type_t { .init(67) }
public var ES_EVENT_TYPE_NOTIFY_READDIR: es_event_type_t { .init(68) }
public var ES_EVENT_TYPE_AUTH_EXCHANGEDATA: es_event_type_t { .init(71) }
public var ES_EVENT_TYPE_AUTH_COPYFILE: es_event_type_t { .init(109) }
public var ES_EVENT_TYPE_NOTIFY_COPYFILE: es_event_type_t { .init(110) }

public struct es_action_type_t: Equatable, RawRepresentable { public var rawValue: UInt32; public init(rawValue: UInt32) { self.rawValue = rawValue } }
public var ES_ACTION_TYPE_AUTH: es_action_type_t { .init(rawValue: 0) }
public var ES_ACTION_TYPE_NOTIFY: es_action_type_t { .init(rawValue: 1) }
public struct es_destination_type_t: Equatable, RawRepresentable { public var rawValue: UInt32; public init(rawValue: UInt32) { self.rawValue = rawValue } }
public var ES_DESTINATION_TYPE_EXISTING_FILE: es_destination_type_t { .init(rawValue: 0) }
public var ES_DESTINATION_TYPE_NEW_PATH: es_destination_type_t { .init(rawValue: 1) }

public struct es_event_open_t { public var fflag: Int32; public var file: UnsafeMutablePointer<es_file_t> }
public struct es_event_close_t { public var modified: Bool; public var target: UnsafeMutablePointer<es_file_t>; public var was_mapped_writable: Bool }
public struct es_event_rename_t {
    public struct __Unnamed_union_destination {
        public struct __Unnamed_struct_new_path { public var dir: UnsafeMutablePointer<es_file_t>; public var filename: es_string_token_t }
        public var existing_file: UnsafeMutablePointer<es_file_t>
        public var new_path: __Unnamed_struct_new_path
    }
    public var source: UnsafeMutablePointer<es_file_t>
    public var destination_type: es_destination_type_t
    public var destination: __Unnamed_union_destination
}
public struct es_event_clone_t { public var source: UnsafeMutablePointer<es_file_t>; public var target_dir: UnsafeMutablePointer<es_file_t>; public var target_name: es_string_token_t }
public struct es_event_copyfile_t {
    public var source: UnsafeMutablePointer<es_file_t>
    public var target_file: UnsafeMutablePointer<es_file_t>?
    public var target_dir: UnsafeMutablePointer<es_file_t>
    public var target_name: es_string_token_t
    public var mode: mode_t
    public var flags: Int32
}
public struct es_event_link_t { public var source: UnsafeMutablePointer<es_file_t>; public var target_dir: UnsafeMutablePointer<es_file_t>; public var target_filename: es_string_token_t }
public struct es_event_unlink_t { public var target: UnsafeMutablePointer<es_file_t>; public var parent_dir: UnsafeMutablePointer<es_file_t> }
public struct es_event_truncate_t { public var target: UnsafeMutablePointer<es_file_t> }
public struct es_event_exchangedata_t { public var file1: UnsafeMutablePointer<es_file_t>; public var file2: UnsafeMutablePointer<es_file_t> }
public struct es_event_readdir_t { public var target: UnsafeMutablePointer<es_file_t> }
// Header (HM:#L656-L705): the trailing `acl` (message version >= 2) is omitted; nothing reads it.
public struct es_event_create_t {
    public struct __Unnamed_union_destination {
        public struct __Unnamed_struct_new_path { public var dir: UnsafeMutablePointer<es_file_t>; public var filename: es_string_token_t; public var mode: mode_t }
        public var existing_file: UnsafeMutablePointer<es_file_t>
        public var new_path: __Unnamed_struct_new_path
    }
    public var destination_type: es_destination_type_t
    public var destination: __Unnamed_union_destination
}
public struct es_event_exec_t { public var target: UnsafeMutablePointer<es_process_t>; public var dyld_exec_path: es_string_token_t; public var script: UnsafeMutablePointer<es_file_t>?; public var cwd: UnsafeMutablePointer<es_file_t> }
public struct es_event_fork_t { public var child: UnsafeMutablePointer<es_process_t> }
public struct es_event_exit_t { public var stat: Int32 }
public struct es_events_t {
    public var open: es_event_open_t
    public var close: es_event_close_t
    public var rename: es_event_rename_t
    public var clone: es_event_clone_t
    public var copyfile: es_event_copyfile_t
    public var link: es_event_link_t
    public var unlink: es_event_unlink_t
    public var truncate: es_event_truncate_t
    public var exchangedata: es_event_exchangedata_t
    public var readdir: es_event_readdir_t
    public var create: es_event_create_t
    public var exec: es_event_exec_t
    public var fork: es_event_fork_t
    public var exit: es_event_exit_t
}
public struct es_message_t {
    public var version: UInt32
    public var time: timespec
    public var mach_time: UInt64
    public var deadline: UInt64
    public var process: UnsafeMutablePointer<es_process_t>
    public var seq_num: UInt64
    public var action_type: es_action_type_t
    public var event_type: es_event_type_t
    public var event: es_events_t
    public var thread: UnsafeMutablePointer<es_thread_t>?
    public var global_seq_num: UInt64
}

public struct es_new_client_result_t: Equatable, RawRepresentable { public var rawValue: UInt32; public init(rawValue: UInt32) { self.rawValue = rawValue } }
public var ES_NEW_CLIENT_RESULT_SUCCESS: es_new_client_result_t { .init(rawValue: 0) }
public var ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: es_new_client_result_t { .init(rawValue: 1) }
public var ES_NEW_CLIENT_RESULT_ERR_INTERNAL: es_new_client_result_t { .init(rawValue: 2) }
public var ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: es_new_client_result_t { .init(rawValue: 3) }
public var ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: es_new_client_result_t { .init(rawValue: 4) }
public var ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: es_new_client_result_t { .init(rawValue: 5) }
public var ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: es_new_client_result_t { .init(rawValue: 6) }
public struct es_return_t: Equatable, RawRepresentable { public var rawValue: UInt32; public init(rawValue: UInt32) { self.rawValue = rawValue } }
public var ES_RETURN_SUCCESS: es_return_t { .init(rawValue: 0) }
public var ES_RETURN_ERROR: es_return_t { .init(rawValue: 1) }
public struct es_respond_result_t: Equatable, RawRepresentable { public var rawValue: UInt32; public init(rawValue: UInt32) { self.rawValue = rawValue } }
public var ES_RESPOND_RESULT_SUCCESS: es_respond_result_t { .init(rawValue: 0) }
public struct es_auth_result_t: Equatable, RawRepresentable { public var rawValue: UInt32; public init(rawValue: UInt32) { self.rawValue = rawValue } }
public var ES_AUTH_RESULT_ALLOW: es_auth_result_t { .init(rawValue: 0) }
public var ES_AUTH_RESULT_DENY: es_auth_result_t { .init(rawValue: 1) }
public struct es_clear_cache_result_t: Equatable, RawRepresentable { public var rawValue: UInt32; public init(rawValue: UInt32) { self.rawValue = rawValue } }
public var ES_CLEAR_CACHE_RESULT_SUCCESS: es_clear_cache_result_t { .init(rawValue: 0) }
public var ES_CLEAR_CACHE_RESULT_ERR_THROTTLE: es_clear_cache_result_t { .init(rawValue: 2) }
public struct es_mute_path_type_t: Equatable, RawRepresentable { public var rawValue: UInt32; public init(rawValue: UInt32) { self.rawValue = rawValue } }
public var ES_MUTE_PATH_TYPE_PREFIX: es_mute_path_type_t { .init(rawValue: 0) }
public var ES_MUTE_PATH_TYPE_LITERAL: es_mute_path_type_t { .init(rawValue: 1) }
public var ES_MUTE_PATH_TYPE_TARGET_PREFIX: es_mute_path_type_t { .init(rawValue: 2) }
public var ES_MUTE_PATH_TYPE_TARGET_LITERAL: es_mute_path_type_t { .init(rawValue: 3) }
public struct es_mute_inversion_type_t: Equatable, RawRepresentable { public var rawValue: UInt32; public init(rawValue: UInt32) { self.rawValue = rawValue } }
public var ES_MUTE_INVERSION_TYPE_PROCESS: es_mute_inversion_type_t { .init(rawValue: 0) }
public var ES_MUTE_INVERSION_TYPE_PATH: es_mute_inversion_type_t { .init(rawValue: 1) }
public var ES_MUTE_INVERSION_TYPE_TARGET_PATH: es_mute_inversion_type_t { .init(rawValue: 2) }
public struct es_mute_inverted_return_t: Equatable, RawRepresentable { public var rawValue: UInt32; public init(rawValue: UInt32) { self.rawValue = rawValue } }
public var ES_MUTE_INVERTED: es_mute_inverted_return_t { .init(rawValue: 0) }
public var ES_MUTE_NOT_INVERTED: es_mute_inverted_return_t { .init(rawValue: 1) }

// MARK: Functions (signatures per DocC Swift declarations)
public typealias es_handler_block_t = (OpaquePointer, UnsafePointer<es_message_t>) -> Void
public func es_new_client(_ client: UnsafeMutablePointer<OpaquePointer?>, _ handler: @escaping es_handler_block_t) -> es_new_client_result_t { ES_NEW_CLIENT_RESULT_ERR_INTERNAL }
public func es_delete_client(_ client: OpaquePointer?) -> es_return_t { ES_RETURN_SUCCESS }
public func es_subscribe(_ client: OpaquePointer, _ events: UnsafePointer<es_event_type_t>, _ event_count: UInt32) -> es_return_t { ES_RETURN_SUCCESS }
public func es_unsubscribe(_ client: OpaquePointer, _ events: UnsafePointer<es_event_type_t>, _ event_count: UInt32) -> es_return_t { ES_RETURN_SUCCESS }
public func es_unsubscribe_all(_ client: OpaquePointer) -> es_return_t { ES_RETURN_SUCCESS }
public func es_respond_auth_result(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ result: es_auth_result_t, _ cache: Bool) -> es_respond_result_t { ES_RESPOND_RESULT_SUCCESS }
public func es_respond_flags_result(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ authorized_flags: UInt32, _ cache: Bool) -> es_respond_result_t { ES_RESPOND_RESULT_SUCCESS }
public func es_clear_cache(_ client: OpaquePointer) -> es_clear_cache_result_t { ES_CLEAR_CACHE_RESULT_SUCCESS }
public func es_mute_process(_ client: OpaquePointer, _ audit_token: UnsafePointer<audit_token_t>) -> es_return_t { ES_RETURN_SUCCESS }
public func es_mute_path(_ client: OpaquePointer, _ path: UnsafePointer<CChar>, _ type: es_mute_path_type_t) -> es_return_t { ES_RETURN_SUCCESS }
public func es_unmute_path(_ client: OpaquePointer, _ path: UnsafePointer<CChar>, _ type: es_mute_path_type_t) -> es_return_t { ES_RETURN_SUCCESS }
public func es_unmute_all_target_paths(_ client: OpaquePointer) -> es_return_t { ES_RETURN_SUCCESS }
public func es_invert_muting(_ client: OpaquePointer, _ mute_type: es_mute_inversion_type_t) -> es_return_t { ES_RETURN_SUCCESS }
public func es_muting_inverted(_ client: OpaquePointer, _ mute_type: es_mute_inversion_type_t) -> es_mute_inverted_return_t { ES_MUTE_NOT_INVERTED }
public func es_exec_arg_count(_ event: UnsafePointer<es_event_exec_t>) -> UInt32 { 0 }
public func es_exec_arg(_ event: UnsafePointer<es_event_exec_t>, _ index: UInt32) -> es_string_token_t { es_string_token_t(length: 0, data: nil) }
#endif
