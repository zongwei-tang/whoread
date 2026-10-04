# EndpointSecurity API — verified facts (collected 2026-10-04)

## Sources, provenance, legend

| Tag | What | Where |
|---|---|---|
| **[DOC]** | Apple DocC JSON behind developer.apple.com (fetched with curl, all 1686 pages under `/documentation/endpointsecurity` crawled). **Reflects the macOS 27 SDK** (it lists macOS 27.0-only symbols). | `https://developer.apple.com/documentation/endpointsecurity/<page>` (JSON: `https://developer.apple.com/tutorials/data/documentation/endpointsecurity/<page>.json`) |
| **[HDR]** | Apple's own SDK header comments (verbatim Apple text), **MacOSX26.5.sdk**, via the third-party mirror `alexey-lysiuk/macos-sdk` @ commit `896cd40df984b847d486723edce50e247385617e`. Same semantics text checked identical in 13.3 and 15.5 SDK headers unless noted. | `https://github.com/alexey-lysiuk/macos-sdk/blob/896cd40df984b847d486723edce50e247385617e/MacOSX26.5.sdk/usr/include/EndpointSecurity/<file>#L<n>` |
| **[MAN]** | Apple's `EndpointSecurity(7)` man page from the SDK (same mirror) | `https://github.com/alexey-lysiuk/macos-sdk/blob/896cd40df984b847d486723edce50e247385617e/MacOSX26.5.sdk/usr/share/man/man7/EndpointSecurity.7` |
| **[WWDC20]** | Apple WWDC20 session 10159 "Build an Endpoint Security app" (transcript) | https://developer.apple.com/videos/play/wwdc2020/10159/ |
| **[WWDC22]** | Apple WWDC22 session 110345 "What's new in Endpoint Security" (transcript) | https://developer.apple.com/videos/play/wwdc2022/110345/ |
| **[SANTA]** | northpolesec/santa @ `af35da14240571fac9a6dca545b01bfc2aa1c014` (2026-10-02) | `https://github.com/northpolesec/santa/blob/af35da14240571fac9a6dca545b01bfc2aa1c014/<path>#L<n>` |

Short URL prefixes used below (always expand them literally):
- `DOC:` = `https://developer.apple.com/documentation/endpointsecurity/`
- `HC:` = `https://github.com/alexey-lysiuk/macos-sdk/blob/896cd40df984b847d486723edce50e247385617e/MacOSX26.5.sdk/usr/include/EndpointSecurity/ESClient.h`
- `HM:` = same dir `/ESMessage.h`, `HMC:` = `/ESMessageCore.h`, `HT:` = `/ESTypes.h`
- `SANTA:` = `https://github.com/northpolesec/santa/blob/af35da14240571fac9a6dca545b01bfc2aa1c014/`

**Read this before using the availability data:** On DocC, enum types, enum constants, structs and struct fields almost never carry an `introducedAt` value. The JSON shows `"name":"macOS"` with no version, rendered below as "macOS (no version given)". That means **not stated**, not "unavailable". Functions do carry versions. For enum-case versions I use the header's `// The following events are available beginning in macOS X` comments.

**Swift import model, as shown by the DocC Swift declarations:** `es_client_t *` is imported as `OpaquePointer`. C enums such as `es_event_type_t`, `es_auth_result_t`, `es_respond_result_t`, `es_return_t`, `es_mute_path_type_t`, `es_mute_inversion_type_t`, `es_action_type_t` and `es_destination_type_t` are imported as **structs** that conform to `BitwiseCopyable, Equatable, Hashable, RawRepresentable, Sendable`. For example, `es_event_type_t` has `init(_ rawValue: UInt32)`, `init(rawValue: UInt32)` and `var rawValue: UInt32`. The constants are global read-only vars, e.g. `var ES_EVENT_TYPE_AUTH_OPEN: es_event_type_t { get }` (DOC:es_event_type_t, DOC:es_event_type_auth_open).

---

## 1. es_new_client, es_new_client_result_t, es_handler_block_t, es_delete_client

### es_new_client — DOC:es_new_client(_:_:)
- Availability: **macOS 10.15** [DOC]
- Swift: `func es_new_client(_ client: UnsafeMutablePointer<OpaquePointer?>, _ handler: @escaping es_handler_block_t) -> es_new_client_result_t`
- C (DOC): `extern es_new_client_result_t es_new_client(es_client_t **client, es_handler_block_t handler);`
- C (HDR, HC:#L667): `es_new_client_result_t es_new_client(es_client_t *_Nullable *_Nonnull client, es_handler_block_t _Nonnull handler);`
- DOC discussion (verbatim):
  > The handler block receives messages serially, and in the order the system delivers them. Returning control from the handler causes Endpoint Security to dequeue the next available message.
  > You can respond to a message out of order by returning control before calling one of the `es_respond`-prefixed functions. For out-of-order responding, your handler must copy the message with `es_copy_message(_:)`.
  > To create a client, your app must have the `com.apple.developer.endpoint-security.client` entitlement. The user also needs to approve your app with Transparency, Consent, and Control (TCC) mechanisms. The user does this in the Security and Privacy pane of System Preferences, by adding the app to Full Disk Access.
  > When you no longer need to receive Endpoint Security messages, destroy the client with `es_delete_client(_:)` to free resources.

  (The DOC page still names the deprecated `es_copy_message`. The header names `es_retain_message`.)
- HDR discussion (verbatim, HC:#L632-L666):
  > Messages are handled strictly serially and in the order they are delivered.
  > Returning control from the handler causes the next available message to be dequeued.
  > Messages can be responded to out of order by returning control before calling es_respond_*.
  > The es_message_t is only guaranteed to live as long as the scope it is passed into.
  > The memory for the given es_message_t is NOT owned by clients and it must not be freed.
  > For out of order responding the handler must retain the message with es_retain_message.
  > Callers are required to be entitled with com.apple.developer.endpoint-security.client.
  > The application calling this interface must also be approved by users via Transparency, Consent & Control (TCC) mechanisms using the Privacy Preferences pane and adding the application to Full Disk Access.
  > When a new client is successfully created, all cached results are automatically cleared.
  >
  > @note When a new client is initialized, there will be a set of paths and a subset of `es_event_type_t` events that are automatically muted by default. Generally, most AUTH event variants are muted but NOTIFY event variants will still be sent to the client. The set of paths muted by default are ones that can have an extremely negative impact to end users if their AUTH events are not allowed in a timely manner (for example, executable paths for processes that are monitored by the watchdogd daemon). It is important to understand that this list is *not* exhaustive and developers using the EndpointSecurity framework can still interfere with critical system components and must use caution to limit user impact. The set of default muted paths and event types may change across macOS releases. It is possible to both inspect and unmute the set of default muted paths and associated event types using the appropriate mute-related API, however it is not recommended to unmute these items.
  >
  > @note The only supported way to check if an application is properly TCC authorized for Full Disk Access is to call es_new_client and handling ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED in a way appropriate to your application. Most applications will want to ask the user for TCC authorization when es_new_client returns ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED. To direct the user to the Full Disk Access section in System Settings, applications can use the following URLs: `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles` (macOS 13 and later) `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles` (until macOS 12) Applications are advised to use the new URL in macOS 13 as the old one may stop working in a future release.

### es_handler_block_t — DOC:es_handler_block_t
- Swift: `typealias es_handler_block_t = (OpaquePointer, UnsafePointer<es_message_t>) -> Void`
- C (DOC): `typedef void (^)(struct es_client_s *, const es_message_t *) es_handler_block_t;`
- C (HDR, HC:#L624): `typedef void (^es_handler_block_t)(es_client_t *_Nonnull, const es_message_t *_Nonnull);`
- DOC (verbatim): "The client that receives the event, as an `es_client_t` pointer. You pass this client to any `es_respond`-prefixed functions that you call in the handler." / "The message to handle, as an `es_message_t` pointer."

### es_new_client_result_t (all cases) — DOC:es_new_client_result_t
- Swift: `struct es_new_client_result_t`. C: `typedef enum { ... } es_new_client_result_t;`. Availability: macOS (no version given).
- Header order and comments (HT:#L343-L358): `ES_NEW_CLIENT_RESULT_SUCCESS`, `ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT`, `ES_NEW_CLIENT_RESULT_ERR_INTERNAL`, `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`, `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`, `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`, `ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS`.
- For the meaning of each case, see §14.

### es_delete_client — DOC:es_delete_client(_:)
- Availability: **macOS 10.15**
- Swift: `func es_delete_client(_ client: OpaquePointer?) -> es_return_t`
- C: `extern es_return_t es_delete_client(es_client_t *client);`
- DOC return value: "A value indicating whether deletion succeeded. `ES_RETURN_ERROR` indicates that shutdown encountered an error, which results in a resource leak."
- HDR (HC:#L676-L679): "ES_RETURN_SUCCESS indicates all resources were freed. ES_RETURN_ERROR indicates an error occurred during shutdown and resources were leaked." **"@note Must be called from the same thread that originally called `es_new_client`."** This note is only in the header, not on DOC.

### es_client_t — DOC:es_client_t
- C: `typedef struct es_client_s es_client_t;` (Swift sees `OpaquePointer`)

### New in macOS 27 (DOC only; not in the 26.5 header)
- `es_new_descendants_client` — DOC:es_new_descendants_client(_:_:). **macOS 27.0**. Swift: `func es_new_descendants_client(_ client: UnsafeMutablePointer<OpaquePointer?>, _ handler: @escaping es_handler_block_t) -> es_new_client_result_t`. DOC: "The returned client receives notify events for the calling process and auth+notify events for its descendant processes ... Requires the com.apple.developer.endpoint-security.client entitlement. / Does NOT require root privilege. / Does NOT require TCC approval." Also: "Path muting and target-path muting work normally."
- `es_sync_client` — DOC:es_sync_client(_:_:). **macOS 27.0**. Swift: `func es_sync_client(_ client: OpaquePointer, _ block: @escaping () -> Void) -> es_return_t`. DOC: "Can NOT be called from the ES handler block of `client`." and "When a program issues a syscall (or similar), it is guaranteed that before control is returned to the caller, the associated ES message has been created and enqueued with all ES clients. Message delivery is asynchronous (even for auth evnts), but enqueing is fully synchronous."

---

## 2. es_subscribe, es_unsubscribe, es_unsubscribe_all (+ es_subscriptions)

| Function | Avail. | Swift (DOC) | C (DOC) |
|---|---|---|---|
| es_subscribe — DOC:es_subscribe(_:_:_:) | 10.15 | `func es_subscribe(_ client: OpaquePointer, _ events: UnsafePointer<es_event_type_t>, _ event_count: UInt32) -> es_return_t` | `extern es_return_t es_subscribe(es_client_t *client, const es_event_type_t *events, uint32_t event_count);` |
| es_unsubscribe — DOC:es_unsubscribe(_:_:_:) | 10.15 | `func es_unsubscribe(_ client: OpaquePointer, _ events: UnsafePointer<es_event_type_t>, _ event_count: UInt32) -> es_return_t` | `extern es_return_t es_unsubscribe(es_client_t *client, const es_event_type_t *events, uint32_t event_count);` |
| es_unsubscribe_all — DOC:es_unsubscribe_all(_:) | 10.15 | `func es_unsubscribe_all(_ client: OpaquePointer) -> es_return_t` | `extern es_return_t es_unsubscribe_all(es_client_t *client);` |
| es_subscriptions — DOC:es_subscriptions(_:_:_:) | 10.15 | `func es_subscriptions(_ client: OpaquePointer, _ count: UnsafeMutablePointer<Int>, _ subscriptions: UnsafeMutablePointer<UnsafeMutablePointer<es_event_type_t>>?) -> es_return_t` | `extern es_return_t es_subscriptions(es_client_t *client, size_t *count, es_event_type_t **subscriptions);` |

- es_subscribe return value (DOC): "`ES_RETURN_ERROR` indicates that the caller couldn't reach the Endpoint Security subsystem or that the request was invalid."
- HDR (HC:#L26-L32): "@note Subscribing to new event types does not remove previous subscriptions." and "@note Subscribing to events is not optional for clients that have opted into early boot mode (see NSEndpointSecurityEarlyBoot in EndpointSecurity(7)). Early boot clients that fail to subscribe to at least one event type will cause early boot to time out, resulting in a bad user experience and risking watchdog timeout panics."
- es_unsubscribe DOC: "After making this call successfully, Endpoint Security continues to deliver messages for any previously-subscribed events that aren't specifically unsubscribed from."
- es_subscriptions DOC: "On return, the caller takes ownership of the memory pointed to by the `subscriptions` parameter, and must free it."
- [WWDC20]: "your client should be prepared to subscribe to all necessary events in a single call to es_subscribe. If you split your events across multiple calls, third-party applications may begin executing before the additional subscriptions are in place and your client can miss events." (This is about early boot.)

---

## 3. Responding: es_respond_auth_result, es_respond_flags_result, es_auth_result_t, es_respond_result_t, caching, deadlines

### es_respond_auth_result — DOC:es_respond_auth_result(_:_:_:_:)
- Availability: **macOS 10.15**
- Swift: `func es_respond_auth_result(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ result: es_auth_result_t, _ cache: Bool) -> es_respond_result_t`
- C: `extern es_respond_result_t es_respond_auth_result(es_client_t *client, const es_message_t *message, es_auth_result_t result, bool cache);`
- DOC param `cache`: "Indicates whether Endpoint Security should cache the result. The caching semantics depend on the specific event type."
- HDR (HC:#L79-L91, verbatim):
  > @param cache Indicates if this result should be cached. The specific caching semantics depend on es_event_type_t. Cache key is generally the involved files, with modifications to those files invalidating the cache entry. A cache hit leads to no AUTH event being produced, while still producing a NOTIFY event normally. The cache argument is ignored for events that do not support caching.
  > @brief Some events must be responded to with `es_respond_flags_result`. Responding to flags events with this function will fail.

### es_respond_flags_result — DOC:es_respond_flags_result(_:_:_:_:)
- Availability: **macOS 10.15**
- Swift: `func es_respond_flags_result(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ authorized_flags: UInt32, _ cache: Bool) -> es_respond_result_t`
- C: `extern es_respond_result_t es_respond_flags_result(es_client_t *client, const es_message_t *message, uint32_t authorized_flags, bool cache);`
- DOC param: "authorized_flags: A `flags` value to apply as a mask on the flags in the event." DOC discussion: "Some events require you to respond with `es_respond_auth_result(_:_:_:_:)`. Responding to such events with this method instead fails with an error."
- HDR (HC:#L101-L124, verbatim):
  > @param authorized_flags A flags value that will mask the flags in event being responded to; pass 0 to deny and UINT32_MAX to allow regardless of what flags are set on the event.
  > ...
  > @note Enabling caching caches authorized_flags. Subsequent cache hits will result in the event being allowed only if the flags of the event are a subset of the flags in authorized_flags, and denied otherwise. As a result, UINT32_MAX should be passed for authorized_flags, unless denying events with certain flags is intentional. A common mistake is passing the flags from the event, which together with caching may result in subsequent events getting unintentionally denied if they have flags set that were not set in the cached authorized_flags.

### Which events use which respond API (HT:#L88-L97, verbatim)
> When a program subscribes to and receives an AUTH-related event, it must respond with an appropriate result indicating whether or not the operation should be allowed to continue. ... Currently, only ES_EVENT_TYPE_AUTH_OPEN must use es_respond_flags_result. All other AUTH events must use es_respond_auth_result.

[WWDC20] says the same: "as of today, only the AUTH OPEN event uses the flags result API." (This is the 26.5 header. The macOS 27 DOC adds new AUTH events, e.g. `ES_EVENT_TYPE_AUTH_XPC_CONNECT` and `ES_EVENT_TYPE_AUTH_BOOTSTRAP_*`. Whether the "only AUTH_OPEN" rule still holds for them is UNVERIFIED.)

### AUTH_OPEN: what if authorized_flags is a strict subset of the requested fflag?
- [HDR]: authorized_flags is a mask over the event's flags. 0 means deny. UINT32_MAX means allow regardless. On a **cache hit**: "allowed only if the flags of the event are a subset of the flags in authorized_flags, and denied otherwise".
- [WWDC20, verbatim]: "es_respond_flags_result is used when an event has a range of options that may be permitted or denied, such as being able to allow a file to be opened with read-only permissions instead of read/write." / "Similarly for flags responses, only the subset of flags set by all clients will be allowed." / "your ES client process should respond with all the flags it will ever permit, not necessarily only the flags requested for an individual event. This has to do with caching" / "If a cached entry exists, the flags from that entry are compared against the requested flags for the new operation, and the result is applied without generating an AUTH message. ... if the process opened the same file for writing in the future, and the cached result still existed, the operation would be automatically denied without generating an AUTH message".
- **UNVERIFIED:** whether a *non-cached* response that masks off some requested flags makes `open(2)` fail with an error, or lets it succeed with fewer access rights. Apple's wording ("mask", "allow ... read-only instead of read/write") does not state the syscall outcome. The cache-hit rule (deny unless subset) suggests the open fails, but no primary source states this for the live response.
- es_event_open_t.fflag (DOC:es_event_open_t/fflag): "This mask differs from the `oflag` values used in `open(2)`. When responding to this event, use `FFLAG` values such as `FREAD` and `FWRITE` instead, rather than `O_RDONLY`, `O_RDWR` and the like." The header says the same (HM:#L294-L307).

### es_auth_result_t — DOC:es_auth_result_t
- Swift `struct es_auth_result_t`. C `typedef enum { ... } es_auth_result_t;`. Cases: `ES_AUTH_RESULT_ALLOW` ("The caller authorizes the event and allows it to continue.") and `ES_AUTH_RESULT_DENY` ("The caller denies authorization to the event and prevents it from continuing."). Header order: ALLOW, then DENY (HT:#L299-L304).

### es_respond_result_t — DOC:es_respond_result_t (header order HT:#L325-L340)
| Case | DOC abstract (verbatim) | HDR comment (verbatim) |
|---|---|---|
| `ES_RESPOND_RESULT_SUCCESS` | Endpoint Security successfully delivered the response. | — |
| `ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT` | The caller provided one or more invalid arguments. | One or more invalid arguments were provided |
| `ES_RESPOND_RESULT_ERR_INTERNAL` | Communication with the Endpoint Security system failed. | Communication with the ES subsystem failed |
| `ES_RESPOND_RESULT_NOT_FOUND` | The system couldn't find the message that the caller sent this response to. | The message being responded to could not be found |
| `ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE` | The caller responded to a message that already received a response. | The provided message has been responded to more than once |
| `ES_RESPOND_RESULT_ERR_EVENT_TYPE` | The caller performed an inappropriate response to the event. | Either an inappropriate response API was used for the event type (ensure using proper es_respond_auth_result or es_respond_flags_result function) or the event is notification only. |

DOC:es_respond_result_err_event_type discussion: "This error occurs if the client attempts to respond to an authorization event using the wrong interface. It also occurs when the client performs any response to a notification-only event."

### Responding twice / late / not at all
- **Twice:** returns `ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE` (see table). No other consequence is documented.
- **Late (after the deadline):** the deadline-miss consequence applies (below). The return value of a late `es_respond_*` call is **UNVERIFIED**. `ES_RESPOND_RESULT_NOT_FOUND` is plausible, but no source says so.
- **Not at all, or past the deadline:**
  - DOC:es_message_t/deadline (verbatim): "If you fail to respond to an event before this deadline, Endpoint Security may terminate the client process, or restart the process if it's a system extension. If your client repeatedly misses deadlines, Endpoint Security may refuse new connections from `es_new_client(_:_:)` altogether."
  - HDR (HM:#L2610-L2615, verbatim): "@field deadline The Mach absolute time before which an auth event must be responded to. If a client fails to respond to auth events prior to the `deadline`, the client will be killed. Each message can contain its own unique deadline, and some deadlines can vary substantially. Clients must take care to inspect the deadline value of each message to know how much time is allotted for processing." The "client will be killed" wording is already in the **10.15** SDK header ("The Mach time before which an auth event must be responded to. If a client fails to respond to auth events prior to the `deadline`, the client will be killed."). So killing has been the documented behavior since ES shipped in 10.15.
  - [WWDC20, verbatim]: "If a client fails to respond before the deadline, the application will be terminated. If your application is a system extension, the launchd job we submit for you will be automatically restarted. ... there is no guarantee that each message allows for the same amount of response time. These values can and will change over time. **When a deadline is missed, an implicit ALLOW is applied as the response, but the result will not be cached**, allowing future operations to be reevaluated."
  - **macOS 27.0 makes this configurable** (DOC only):
    - `es_deadline_miss_mode_t` (DOC:es_deadline_miss_mode_t): "Determines how the system responds when a client fails to respond to an auth event within the deadline." Cases: `ES_DEADLINE_MISS_MODE_KILL` ("Kill the client when it fails to respond to an auth event (default behavior)"), `ES_DEADLINE_MISS_MODE_FAIL_OPEN` ("Allow the operation when client fails to respond, but don't kill the client"), `ES_DEADLINE_MISS_MODE_FAIL_CLOSED` ("Deny the operation when client fails to respond, but don't kill the client").
    - `func es_set_deadline_miss_mode(_ client: OpaquePointer, _ mode: es_deadline_miss_mode_t) -> es_return_t` (macOS 27.0, DOC:es_set_deadline_miss_mode(_:_:)): "The default mode is ES_DEADLINE_MISS_MODE_KILL." / "This allows clients to defer deadline management to the kernel instead of implementing their own timeout mechanisms." / "**When `ES_DEADLINE_MISS_MODE_FAIL_CLOSED` is used, if an `AUTH` message is dropped because the message queue was full, it will be `DENY`ed instead of the usual `ALLOW` behaviour.**" So by default, AUTH messages dropped because of a full queue are allowed.
    - `func es_get_deadline_miss_mode(_ client: OpaquePointer, _ mode: UnsafeMutablePointer<es_deadline_miss_mode_t>) -> es_return_t` (macOS 27.0)
    - `func es_set_deadline_max_milliseconds(_ client: OpaquePointer, _ events: UnsafePointer<es_event_type_t>, _ event_count: UInt32, _ milliseconds: UInt32) -> es_return_t` (macOS 27.0): "This allows clients to configure lower per-event-type deadlines ... The kernel will automatically unblock operations based on the client's deadline miss mode when the deadline expires." It returns ES_RETURN_ERROR "if milliseconds exceeds system default".
    - `es_get_deadline_max_milliseconds`, `es_set/get_deadline_min_milliseconds` (macOS 27.0; min only for descendants clients).

### What the `cache` flag caches, and the cache key per event
- The cache is **global and shared by all clients**:
  - DOC:es_clear_cache(_:): "Endpoint Security shares caches across all clients"
  - [WWDC20]: "Many of the AUTH events can cache the combined result from the ES client responses, and this is stored in a single global cache shared across all ES clients. The cache strategy used by EndpointSecurity is best effort, and entries may expire at any time. EndpointSecurity tracks several operations, and will automatically invalidate cached entries, for example, if a file is written, truncated, deleted and many more. While we don't guarantee responses will be cached, **if an ES client sets the cache flag in the response APIs to false, ES will guarantee not to cache that result, even if another client does request that it be cached.**"
- What a hit does [HDR]: "A cache hit leads to no AUTH event being produced, while still producing a NOTIFY event normally."
- Invalidation [HDR]: "Cache key is generally the involved files, with modifications to those files invalidating the cache entry."
- The cache is cleared automatically on client creation [HDR es_new_client] and, per [WWDC20], "ES will automatically clear the cache when a new client connects or an existing client disconnects."
- **Per-event cache notes.** These come from the HDR only. The DOC struct pages do NOT include the "Cache key" notes. The notes are absent in the 12.3 SDK header and present from 13.3 on.

| Event struct | Header note (verbatim) | Source |
|---|---|---|
| es_event_open_t | `Cache key for this event type:  (process executable file, file that will be opened)` | HM:#L304 |
| es_event_exec_t | `Cache key for this event type:  (process executable file, target executable file)` + `Caching is not supported when `script` is nonnull` | HM:#L245-L246 |
| es_event_readdir_t | `Cache key for this event type:  (process executable file, target directory)` | HM:#L1099 |
| es_event_rename_t | `This event type does not support caching.` | HM:#L516 |
| es_event_clone_t | `This event type does not support caching.` | HM:#L1044 |
| es_event_copyfile_t | `This event type does not support caching.` | HM:#L1068 |
| es_event_link_t | `This event type does not support caching.` | HM:#L385 |
| es_event_unlink_t | `This event type does not support caching.` | HM:#L350 |
| es_event_truncate_t | `This event type does not support caching.` | HM:#L750 |
| es_event_exchangedata_t | `This event type does not support caching.` | HM:#L725 |
| es_event_create_t | `This event type does not support caching.` | HM:#L686 |
| es_event_close_t / fork / exit | `This event type does not support caching (notify-only).` | HM:#L634, #L441, #L712 |

Other events with cache keys in 26.5: mmap (process exe, source file), mount (process exe, mount point), chdir, chroot, getattrlist, getextattr, listextattr, setmode, setflags, setowner, utimes, fsgetpath, get_task, get_task_read, proc_check, searchfs, uipc_connect. In the 13.3 header `es_event_signal_t` also had a cache key. In 26.5 it says "does not support caching".

### Multiple clients and introspection [WWDC20]
- "the responses from all the clients are combined by applying the most restrictive response, so if you have four clients respond to an event with ALLOW but one wants to DENY, the overall result is to deny the operation."
- "ES does not send introspective AUTH events as this would lead to trivial deadlocks. The events will be implicitly allowed. We will, however, send NOTIFY messages for events instigated by your process."
- "AUTH messages are only delivered if there is no cached result and the message isn't being delivered to the same process that instigated the event. Neither AUTH nor NOTIFY messages are delivered if the instigating process is muted." / "If there were no ES clients subscribed to the AUTH variant, or no AUTH variant exists for the event, the result is implicitly allowed."

---

## 4. es_retain_message / es_release_message (and deprecated es_copy_message / es_free_message / es_message_size)

| Function | Availability (DOC) | Swift | C |
|---|---|---|---|
| es_retain_message — DOC:es_retain_message(_:) | **macOS 11.0** | `func es_retain_message(_ msg: UnsafePointer<es_message_t>)` | `extern void es_retain_message(const es_message_t *msg);` |
| es_release_message — DOC:es_release_message(_:) | **macOS 11.0** | `func es_release_message(_ msg: UnsafePointer<es_message_t>)` | `extern void es_release_message(const es_message_t *msg);` |
| es_copy_message — DOC:es_copy_message(_:) | 10.15, **deprecated 11.0** ("Use `es_retain_message(_:)` to retain a message.") | `func es_copy_message(_ msg: UnsafePointer<es_message_t>) -> UnsafeMutablePointer<es_message_t>?` | `extern es_message_t *es_copy_message(const es_message_t *msg);` |
| es_free_message — DOC:es_free_message(_:) | 10.15, **deprecated 11.0** ("Use `es_release_message(_:)` to release a message.") | `func es_free_message(_ msg: UnsafeMutablePointer<es_message_t>)` | `extern void es_free_message(es_message_t *msg);` |
| es_message_size — DOC:es_message_size(_:) | 10.15, **deprecated 11.0** | `func es_message_size(_ msg: UnsafePointer<es_message_t>) -> Int` | `extern size_t es_message_size(const es_message_t *msg);` |

- es_retain_message DOC: "If you asynchronously process the message provided to the event-handler block of `es_new_client(_:_:)`, you must retain the message." HDR (HM:#L2747-L2752): "Retains the given es_message_t, extending its lifetime until released with `es_release_message`. ... @note It is necessary to retain a message when the es_message_t provided in the event handler block of `es_new_client` will be processed asynchronously."
- es_free_message DOC: "Only free messages you explicitly copied with `es_copy_message(_:)`." / "[Warning] Freeing a message from inside a handler block will cause your app to crash."
- es_copy_message HDR (HM:#L2715-L2732): since 11.0 it actually "Retains an es_message_t, returning a non-const pointer ... It is invalid to attempt to write to the returned es_message_t, despite being non-const, and doing so will result in a crash."
- es_message_size deprecation (DOC): "Don't use `es_message_size(_:)` in conjunction with attempting to copy a message; doing so will result in use-after-free bugs."

---

## 5. es_clear_cache — DOC:es_clear_cache(_:)
- Availability: **macOS 10.15**
- Swift: `func es_clear_cache(_ client: OpaquePointer) -> es_clear_cache_result_t`
- C: `extern es_clear_cache_result_t es_clear_cache(es_client_t *client);`
- DOC: "Clears all cached results for all clients." / "Endpoint Security shares caches across all clients, so you can provide any valid client as the parameter to this function."
- HDR (HC:#L608-L613): "This functions clears the shared cache for all ES clients and is hence rate limited. If es_clear_cache is called too frequently it will return ES_CLEAR_CACHE_RESULT_ERR_THROTTLE It is permissible to pass any valid es_client_t object created by `es_new_client`"
- `es_clear_cache_result_t` (DOC:es_clear_cache_result_t; HT:#L362-L370): `ES_CLEAR_CACHE_RESULT_SUCCESS` ("Clearing the cache succeeded."), `ES_CLEAR_CACHE_RESULT_ERR_INTERNAL` ("Communication with the Endpoint Security system failed."), `ES_CLEAR_CACHE_RESULT_ERR_THROTTLE` ("Clearing the cache failed because the rate of calls was too high." / "If you receive this response, slow down the rate at which you make calls to `es_clear_cache(_:)`.")
- [WWDC20]: "we do not support invalidating individual cache entries."

---

## 6. Process muting

| Function | Avail. | Swift (DOC) |
|---|---|---|
| es_mute_process — DOC:es_mute_process(_:_:) | 10.15 | `func es_mute_process(_ client: OpaquePointer, _ audit_token: UnsafePointer<audit_token_t>) -> es_return_t` |
| es_mute_process_events — DOC:es_mute_process_events(_:_:_:_:) | **12.0** | `func es_mute_process_events(_ client: OpaquePointer, _ audit_token: UnsafePointer<audit_token_t>, _ events: UnsafePointer<es_event_type_t>, _ event_count: Int) -> es_return_t` |
| es_unmute_process — DOC:es_unmute_process(_:_:) | 10.15 | `func es_unmute_process(_ client: OpaquePointer, _ audit_token: UnsafePointer<audit_token_t>) -> es_return_t` |
| es_unmute_process_events — DOC:es_unmute_process_events(_:_:_:_:) | 12.0 | `func es_unmute_process_events(_ client: OpaquePointer, _ audit_token: UnsafePointer<audit_token_t>, _ events: UnsafePointer<es_event_type_t>, _ event_count: Int) -> es_return_t` |
| es_muted_processes_events — DOC:es_muted_processes_events(_:_:) | 12.0 | `func es_muted_processes_events(_ client: OpaquePointer, _ muted_processes: UnsafeMutablePointer<UnsafeMutablePointer<es_muted_processes_t>?>) -> es_return_t` |
| es_release_muted_processes — DOC:es_release_muted_processes(_:) | 12.0 | `func es_release_muted_processes(_ muted_processes: UnsafeMutablePointer<es_muted_processes_t>)` |
| es_muted_processes (deprecated) — DOC:es_muted_processes(_:_:_:) | 10.15, **deprecated 12.0** ("Use `es_muted_processes_events(_:_:)` instead.") | `func es_muted_processes(_ client: OpaquePointer, _ count: UnsafeMutablePointer<Int>, _ audit_tokens: UnsafeMutablePointer<UnsafeMutablePointer<audit_token_t>>?) -> es_return_t` |

Notes:
- `event_count` is `UInt32` for subscribe/unsubscribe, but **`Int` (size_t)** for the `*_events` mute APIs.
- C: `extern es_return_t es_mute_process(es_client_t *client, const audit_token_t *audit_token);` and `extern es_return_t es_mute_process_events(es_client_t *client, const audit_token_t *audit_token, const es_event_type_t *events, size_t event_count);`
- Structs (HT:#L462-L486; DOC:es_muted_process_t, DOC:es_muted_processes_t): `es_muted_process_t { audit_token_t audit_token; size_t event_count; const es_event_type_t *events; }` and `es_muted_processes_t { size_t count; const es_muted_process_t *processes; }`.
- es_muted_processes HDR (HC:#L212-L224): "If there are no muted processes and the call completes successfully, `*count` is set to 0 and `*audit_token` is set to NULL. @note The audit tokens are returned in the same state as they were passed to `es_mute_process` and may not accurately reflect the current state of the respective processes."
- [WWDC20]: "The EndpointSecurity subsystem will automatically track process exits and remove them from your client's set of muted processes." / "Muting by process audit token is generally a better way to mute events without as much overhead."

---

## 7. Path muting (executable paths and target paths)

| Function | Avail. | Swift (DOC) |
|---|---|---|
| es_mute_path — DOC:es_mute_path(_:_:_:) | **12.0** | `func es_mute_path(_ client: OpaquePointer, _ path: UnsafePointer<CChar>, _ type: es_mute_path_type_t) -> es_return_t` |
| es_mute_path_events — DOC:es_mute_path_events(_:_:_:_:_:) | 12.0 | `func es_mute_path_events(_ client: OpaquePointer, _ path: UnsafePointer<CChar>, _ type: es_mute_path_type_t, _ events: UnsafePointer<es_event_type_t>, _ event_count: Int) -> es_return_t` |
| es_unmute_path — DOC:es_unmute_path(_:_:_:) | 12.0 | `func es_unmute_path(_ client: OpaquePointer, _ path: UnsafePointer<CChar>, _ type: es_mute_path_type_t) -> es_return_t` |
| es_unmute_path_events — DOC:es_unmute_path_events(_:_:_:_:_:) | 12.0 | `func es_unmute_path_events(_ client: OpaquePointer, _ path: UnsafePointer<CChar>, _ type: es_mute_path_type_t, _ events: UnsafePointer<es_event_type_t>, _ event_count: Int) -> es_return_t` |
| es_unmute_all_paths — DOC:es_unmute_all_paths(_:) | 10.15 | `func es_unmute_all_paths(_ client: OpaquePointer) -> es_return_t` |
| es_unmute_all_target_paths — DOC:es_unmute_all_target_paths(_:) | **13.0** | `func es_unmute_all_target_paths(_ client: OpaquePointer) -> es_return_t` |
| es_muted_paths_events — DOC:es_muted_paths_events(_:_:) | 12.0 | `func es_muted_paths_events(_ client: OpaquePointer, _ muted_paths: UnsafeMutablePointer<UnsafeMutablePointer<es_muted_paths_t>>?) -> es_return_t` (the nullability differs from the processes variant; this is copied as shown) |
| es_release_muted_paths — DOC:es_release_muted_paths(_:) | 12.0 | `func es_release_muted_paths(_ muted_paths: UnsafeMutablePointer<es_muted_paths_t>)` |
| es_mute_path_prefix — DOC:es_mute_path_prefix(_:_:) | 10.15, **deprecated 12.0** ("Use `es_mute_path(_:_:_:)` or `es_mute_path_events(_:_:_:_:_:)` instead.") | `func es_mute_path_prefix(_ client: OpaquePointer, _ path_prefix: UnsafePointer<CChar>) -> es_return_t` |
| es_mute_path_literal — DOC:es_mute_path_literal(_:_:) | 10.15, **deprecated 12.0** (same message) | `func es_mute_path_literal(_ client: OpaquePointer, _ path_literal: UnsafePointer<CChar>) -> es_return_t` |

C declarations (DOC): `extern es_return_t es_mute_path(es_client_t *client, const char *path, es_mute_path_type_t type);`, `extern es_return_t es_mute_path_events(es_client_t *client, const char *path, es_mute_path_type_t type, const es_event_type_t *events, size_t event_count);`, `extern es_return_t es_unmute_all_target_paths(es_client_t *client);`

### es_mute_path_type_t — DOC:es_mute_path_type_t, HT:#L411-L436
- DOC lists only PREFIX and LITERAL under "Path Types". The TARGET cases exist as separate DOC pages (DOC:es_mute_path_type_target_prefix, DOC:es_mute_path_type_target_literal) with **macOS 13.0** (Mac Catalyst 16.1) and **empty abstracts**.
- Header (verbatim, in order):
  > @note: Be careful with symlinks, muting happens AFTER symlink resolution. muting '/tmp' won't work because it's a symlink to '/private/tmp'
  - `ES_MUTE_PATH_TYPE_PREFIX`: "Value to describe a prefix for the path to the instigating program eg `/bin` would match `/bin/ls` and `/bin/sleep` This is a type of *program* muting. It could match multiple proccesses"
  - `ES_MUTE_PATH_TYPE_LITERAL`: "Value to describe the exact path to the instigating program *must match exactly* eg `/bin/ls`would match `/bin/ls` but NOT match `/bin/lsa`"
  - `ES_MUTE_PATH_TYPE_TARGET_PREFIX API_AVAILABLE(macos(13.0))`: "Value to describe a target path prefix target here has a very specific meaning @see es_mute_path() briefly, this type of muting matches the *argument(s)* to syscalls, rather than the instigating program prefix matching means `/private/tmp` would match `open(/private/tmp/cake)`"
  - `ES_MUTE_PATH_TYPE_TARGET_LITERAL API_AVAILABLE(macos(13.0))`: "Behaves just like ES_MUTE_PATH_TYPE_TARGET_PREFIX except that the target path must match *exactly* eg `/private/tmp/foo` would match `open(/private/tmp/foo)` but NOT match `open(/private/tmp/foobar)`"
- es_muted_path_t (HT; DOC:es_muted_path_t): `{ es_mute_path_type_t type; size_t event_count; const es_event_type_t *events; es_string_token_t path; }`. es_muted_paths_t: `{ size_t count; const es_muted_path_t *paths; }`.

### Key HDR notes on path muting (verbatim)
- es_mute_path (HC:#L270-L277):
  > @note Path-based muting applies to the real and potentially firmlinked path of a file as seen by VFS, and as available from fcntl(2) F_GETPATH. No special provisions are made for files with multiple ("hard") links, or for symbolic links. In particular, when using inverted target path muting to monitor a particular path for writing, you will need to check if the file(s) of interest are also reachable via additional hard links outside of the paths you are observing.
- es_mute_path_events (HC:#L350-L354):
  > when using ES_MUTE_PATH_TYPE_TARGET_PREFIX and ES_MUTE_PATH_TYPE_TARGET_LITERAL not all events are supported. Target muting a path for an event type that does not support target muting is a no-op. If at least one event type was muted for a target path then ES_RETURN_SUCCESS is returned. If all specified event types do not support target muting ES_RETURN_ERROR is returned. See es_mute_path for the list of events that support target path muting.
- es_unmute_all_paths (HC:#L404): "@note Only unmutes executable paths. To unmute target paths see: `es_unmute_all_target_paths`."
- es_unmute_path (HC:#L428-L434):
  > @note Muting and unmuting operations logically work on a set of (path_type, path, es_event_type_t) tuples Subtracting an element from the set that is not present has no effect For example if `(literal, /foo/bar/, *)` is muted Then `(prefix, /foo, *)` is unmuted the mute set is still: `(literal, /foo/bar, *)`. Prefixes only apply to mute evaluation not to modifications of the mute set.
- [WWDC20]: "While we employ data structures with fast lookup operations, adding a large number of paths can potentially have an adverse affect on performance."
- **Target-path definition per event:** see §8.

---

## 8. Mute inversion; multi-target-path semantics (CRUCIAL)

### Declarations
- `es_invert_muting` — DOC:es_invert_muting(_:_:), **macOS 13.0**, DOC abstract **empty**. Swift: `func es_invert_muting(_ client: OpaquePointer, _ mute_type: es_mute_inversion_type_t) -> es_return_t`. C: `extern es_return_t es_invert_muting(es_client_t *client, es_mute_inversion_type_t mute_type);`
- `es_muting_inverted` — DOC:es_muting_inverted(_:_:), **macOS 13.0**, abstract empty. Swift: `func es_muting_inverted(_ client: OpaquePointer, _ mute_type: es_mute_inversion_type_t) -> es_mute_inverted_return_t`
- `es_mute_inversion_type_t` — DOC:es_mute_inversion_type_t (macOS 13.0, Mac Catalyst 16.1). Header (HT:#L502-L507): `ES_MUTE_INVERSION_TYPE_PROCESS, ES_MUTE_INVERSION_TYPE_PATH, ES_MUTE_INVERSION_TYPE_TARGET_PATH, ES_MUTE_INVERSION_TYPE_LAST } es_mute_inversion_type_t API_AVAILABLE(macos(13.0));`
- `es_mute_inverted_return_t` (HT:#L509-L516): `ES_MUTE_INVERTED` ("The type of muted queried was inverted"), `ES_MUTE_NOT_INVERTED` ("The type of muted queried was not inverted"), `ES_MUTE_INVERTED_ERROR` ("There was an error querying mute inversion state").
- Note: `es_invert_muting` **toggles** the state ("Invert the mute state of a given mute dimension"). Santa therefore checks `es_muting_inverted` before calling it (§Secondary).

### Apple DOC has NO prose for any of this. All semantics below are verbatim from the HEADER (HC).

**Multi-target events (HC:#L280-L285, es_mute_path @discussion, verbatim):**
> When using the path types ES_MUTE_PATH_TYPE_TARGET_PREFIX and ES_MUTE_PATH_TYPE_TARGET_LITERAL Not all events are supported. Furthermore the interpretation of target path is contextual. For events with more than one target path (such as exchangedata) the behavior depends on the mute inversion state Under normal muting the event is suppressed only if ALL paths are muted When target path muting is inverted the event is selected if ANY target path is muted For example a rename will be suppressed if and only if both the source path and destination path are muted. Supported events are listed below. For each event the target path is defined as:

The 13.3 header has the same text, with line breaks that make it easier to read:
> For events with more than one target path (such as exchangedata) the behavior depends on the mute inversion state
>   Under normal muting the event is suppressed only if ALL paths are muted
>   When target path muting is inverted the event is selected if ANY target path is muted
> For example a rename will be suppressed if and only if both the source path and desintiation path are muted.

**So:** without inversion, a multi-target event is delivered unless *all* of its target paths are muted. With target-path inversion, it is delivered if *any* target path is in the (now "selected") set.

**Target-path definition per event (HC:#L287-L330, verbatim):**
```
EXEC: The file being executed
OPEN: The file being opened
MMAP: The file being memory mapped
RENAME: Both the source and destination path.
SIGNAL: The path of the process being signalled
UNLINK: The file being unlinked
CLOSE: The file being closed
CREATE: The path to the file that will be created or replaced
GET_TASK: The path of the process for which the task port is being retrieved
LINK: Both the source and destination path
SETATTRLIST / SETEXTATTR / SETFLAGS / SETMODE / SETOWNER: The file for which ... is being set
WRITE: The file being written to
READLINK: The symbolic link being resolved
TRUNCATE: The file being truncated
CHDIR: The new working directory
GETATTRLIST / STAT / ACCESS / CHROOT / UTIMES: (the file concerned)
CLONE: Both the source file and target path
FCNTL: The file under file control
GETEXTATTR / LISTEXTATTR: The file for which extended attributes are being retrieved/listed
READDIR The directory for whose contents will be read
DELETEEXTATTR The file for which extended attribues will be deleted
DUP: The file being duplicated
UIPC_BIND: The path to the unix socket that will be created
UIPC_CONNECT: The file that the unix socket being connected is bound to
EXCHANGEDATA: The path of both file1 and file2
SETACL: The file for which ACLs are being set
PROC_CHECK / PROC_SUSPEND_RESUME / GET_TASK_NAME / TRACE / REMOTE_THREAD_CREATE / GET_TASK_READ / GET_TASK_INSPECT: The path of the (target) process
SEARCHFS: The path of the volume which will be searched
COPYFILE: The path to the source file and the path to either the new file to be created or the existing file to be overwritten
```
(The lines joined with "/" are condensed. The exact per-line wording is at HC:#L287-L330.) **FORK and EXIT are not in the list**, so target-path muting does not apply to them.

**How inversion combines with other muting (HC:#L497-L513, verbatim):**
> Inverting muting can be used to create a client that monitors a specific process(es) or set of directories When muting is inverted it still combines with other types of muting using OR, and inversion happens first.
> Consider a series of inputs for a system where pid 12 is muted, process muting is inverted, and /bin/bash is also path muted:
>   (12, /bin/foo)  MATCHING (true, false)  INVERSION (false, false) || false → event is not suppressed
>   (13, /bin/foo)  MATCHING (false, false) INVERSION (true, false)  || true  → event is suppressed
>   (12, /bin/bash) MATCHING (true, true)   INVERSION (false, true)  || true  → event is suppressed
> Note that because muting is combined using OR even when pid 12 is being selected using inverted process muting, (12, /bin/bash) is still suppressed because the path is muted

**Kernel evaluation flowchart (HC:#L516-L575; transcribed from the ASCII chart):**
1. Not subscribed → suppress.
2. Process muted? If yes and proc muting NOT inverted → suppress. If no and proc muting IS inverted → suppress.
3. Executable path muted? Same rule with path inversion.
4. Event supports target path muting? If no → deliver.
   - Target muting inverted → "Are ANY target paths muted?" No → suppress. Yes → deliver.
   - Target muting not inverted → "Are ALL target paths muted?" Yes → suppress. No → deliver.

**Default mute set warning (HC:#L577-L585, verbatim):**
> @note Mute inversion does NOT clear the default mute set. When a new `es_client_t` is created certain paths are muted by default. This is known as "the default mute set". The default mute set exists to protect ES clients from deadlocks, and to prevent watchdog timeout panics. Creating a new client and calling `es_invert_muting(c, ES_MUTE_INVERSION_TYPE_PATH)` will result in the default mute set being selected rather than muted. In most cases this is unintended. Consider calling `es_unmute_all_paths` before inverting process path muting. Consider calling `es_unmute_all_target_paths` before inverting target path muting. Make sure the client has no auth subscriptions before doing so. If desired the default mute set can be saved using `es_muted_paths_events` and then restored after inverting again.

**[WWDC22] corroboration:** "Effectively, you can now select processes, executable paths, or target paths you are interested in to only receive events that match -- instead of don't match -- anything you've muted. ... Here's how you would use es_invert_muting to invert muting for target paths. You would then proceed to remove previously existing target paths from the mute set, and then select only events with the target-path prefix that you are interested in."

---

## 9. es_message_t and es_action_type_t

### es_message_t — DOC:es_message_t, HDR HM:#L2599-L2689
Header struct (verbatim):
```c
typedef struct {
	uint32_t version;
	struct timespec time;
	uint64_t mach_time;
	uint64_t deadline;
	es_process_t *_Nonnull process;
	uint64_t seq_num; /* field available only if message version >= 2 */
	es_action_type_t action_type;
	union {
		es_event_id_t auth;
		es_result_t notify;
	} action;
	es_event_type_t event_type;
	es_events_t event;
	es_thread_t *_Nullable thread; /* field available only if message version >= 4 */
	uint64_t global_seq_num;       /* field available only if message version >= 4 */
	uint64_t opaque[];             /* Opaque data that must not be accessed directly */
} es_message_t;
```
Swift field types (DOC member pages):
| Field | Swift | DOC note (verbatim) |
|---|---|---|
| version | `var version: UInt32` | "Clients wishing to be backward-compatible with future changes to Endpoint Security should inspect the version to ensure they don't try to access fields that aren't available." |
| time | `var time: timespec` | "The time the event occurred, expressed as a Darwin time value." |
| mach_time | `var mach_time: UInt64` | "The time the event occurred, as a Mach time value." |
| deadline | `var deadline: UInt64` | see §3 |
| process | `var process: UnsafeMutablePointer<es_process_t>` | "The process that performed the action defined in a message." |
| seq_num | `var seq_num: UInt64` | "...This field is available if the message version is greater than `2`." (HDR says `>= 2`) |
| action_type | `var action_type: es_action_type_t` | |
| action | `var action: es_message_t.__Unnamed_union_action` | "The action is a `union` of an `es_event_id_t` named `auth` and an `es_result_t` named `notify`." |
| event_type | `var event_type: es_event_type_t` | |
| event | `var event: es_events_t` | |
| thread | `var thread: UnsafeMutablePointer<es_thread_t>?` | "This field may be NULL when threading doesn't apply." |
| global_seq_num | `var global_seq_num: UInt64` | "...This field is available if the message version is greater than `4`." (HDR says `>= 4`) |
| opaque | (C only) `uint64_t opaque[];` | "Apps shouldn't access this field." |

- **Discrepancy:** DOC says "greater than 2/4". The HDR says "version >= 2/4" and requires: "all access must be guarded at runtime by checking the value of the message version field, e.g. `if (msg->version >= 2) { acl = msg->event.create.acl; }`" (HM:#L2655-L2662). Use `>=` as the header says.
- **Mach time units (HM:#L2663-L2670, verbatim):** "Fields using Mach time are in the resolution matching the ES client's architecture. This means they can be compared to mach_absolute_time() and converted to nanoseconds with the help of mach_timebase_info(). Further note that on Apple silicon, x86_64 clients running under Rosetta 2 will see Mach times in a different resolution than native arm64 clients." `deadline` is "The Mach absolute time before which an auth event must be responded to" (HDR). The DOC deadline page does not state the unit.
- HDR action field: "For auth events, contains the opaque auth ID that must be supplied when responding to the event. For notify events, describes the result of the action."
- HDR note: "For events that can be authorized there are unique NOTIFY and AUTH event types for the same event data, eg: event.exec is the correct union label for both ES_EVENT_TYPE_AUTH_EXEC and ES_EVENT_TYPE_NOTIFY_EXEC event types."
- es_result_t (HM:#L2586-L2597): `{ es_result_type_t result_type; union { es_auth_result_t auth; uint32_t flags; uint8_t reserved[32]; } result; }`. es_result_type_t cases: `ES_RESULT_TYPE_AUTH`, `ES_RESULT_TYPE_FLAGS`.
- es_event_id_t (HT:#L11-L13): `typedef struct { uint8_t reserved[32]; } es_event_id_t;`
- es_thread_t (DOC:es_thread_t): `var thread_id: UInt64` / `uint64_t thread_id;`

### es_action_type_t — DOC:es_action_type_t
- `ES_ACTION_TYPE_AUTH` ("The authentication action type."), `ES_ACTION_TYPE_NOTIFY` ("The notification action type."). HT:#L15-L18.

---

## 10. es_process_t, es_file_t, es_string_token_t

### es_process_t — DOC:es_process_t; HDR HMC:#L36-L115 (moved to ESMessageCore.h in the 26.x SDK)
Header struct (26.5, verbatim):
```c
typedef struct {
	audit_token_t audit_token;
	pid_t ppid;
	pid_t original_ppid;
	pid_t group_id;
	pid_t session_id;
	uint32_t codesigning_flags;
	bool is_platform_binary;
	bool is_es_client;
	es_cdhash_t cdhash;
	es_string_token_t signing_id;
	es_string_token_t team_id;
	es_file_t *_Nonnull executable;
	es_file_t *_Nullable tty;                           /* field available only if message version >= 2 */
	struct timeval start_time;                          /* field available only if message version >= 3 */
	audit_token_t responsible_audit_token;              /* field available only if message version >= 4 */
	audit_token_t parent_audit_token;                   /* field available only if message version >= 4 */
	es_cs_validation_category_t cs_validation_category; /* field available only if message version >= 10 */
} es_process_t;
```
Swift types (DOC): `audit_token: audit_token_t`, `ppid: pid_t`, `original_ppid: pid_t`, `group_id: pid_t`, `session_id: pid_t`, `codesigning_flags: UInt32`, `is_platform_binary: Bool`, `is_es_client: Bool`, `cdhash: es_cdhash_t`, `signing_id: es_string_token_t`, `team_id: es_string_token_t`, `executable: UnsafeMutablePointer<es_file_t>`, `tty: UnsafeMutablePointer<es_file_t>?`, `start_time: timeval`, `responsible_audit_token: audit_token_t`, `parent_audit_token: audit_token_t`, `cs_validation_category: es_cs_validation_category_t`. **macOS 27 DOC also lists `cdhash_full: es_token_t` ("Structure buffer with size") and `reserved` (C: `uint8_t reserved[16];`).** These are not in the 26.5 header. The message version that gates `cdhash_full` is UNVERIFIED.
- `es_cdhash_t` = `typedef uint8_t es_cdhash_t[20];` (HT). In Swift this is a 20-tuple.
- Per-field notes (verbatim):
  - ppid (HDR): "Parent pid of the process. It is recommended to instead use the parent_audit_token field."
  - original_ppid (DOC): "This field stays constant, even if the process' parent changes."
  - is_es_client (HDR): "Indicates this process has the Endpoint Security entitlement." (DOC: "...whether the process connects to the Endpoint Security subsystem.")
  - is_platform_binary (DOC): "For the purposes of this value, a "platform binary" is one signed with Apple certificates."
  - codesigning_flags (DOC): "See `kern/cs_blobs.h` in the macOS SDK inside of the Xcode app bundle for definitions of these flags."
  - tty (DOC): "This field is available if the message version is greater than `2`." (HDR: `>= 2`)
  - start_time (DOC): "This value represents the time that a fork call created the process. This field is only available if the message `version` is `3` or greater."
  - responsible_audit_token (DOC): "The responsible process may be this process itself, if there's no responsible process or the responsible process already exited. This field is only available if the message `version` is `4` or greater."
  - parent_audit_token (DOC): "This field is only available if the message `version` is `4` or greater."
  - cs_validation_category (DOC): "Indicates the code signature validation policy that was applied to a binary". HDR: version >= 10. It is present in the 26.5 header and absent in the 15.5 header.
- HDR discussion: "The tuple (pid, pidversion) identifies a specific process execution, and should be used to link events to the process that emitted them." and "Clients should take caution when processing events where `is_es_client` is true. If multiple ES clients exist, actions taken by one client could trigger additional actions by the other client, causing a potentially infinite cycle."

### es_file_t — DOC:es_file_t; HMC:#L13-L33
```c
typedef struct {
	es_string_token_t path;
	bool path_truncated;
	struct stat stat;
} es_file_t;
```
- Swift: `var path: es_string_token_t`, `var path_truncated: Bool`, `var stat: stat`.
- HDR: "For the FAT family of filesystems the `stat.st_ino` field is set to 999999999 for empty files" / "For files with a link count greater than 1, the absolute path given may not be the only absolute path that exists, and which hard link the emitted path points to is undefined." / "Overlong paths are truncated at a maximum length that currently is 16K, though that number is not considered API and may change at any time."
- DOC path_truncated: "If Endpoint Security truncated the full file path when assigning the `path` field, this value is `true`."

### es_string_token_t — DOC:es_string_token_t; HT:#L402-L407
- C: `typedef struct { size_t length; const char *data; } es_string_token_t;` with comment "Length of the `data` field. Equivalent to strlen()."
- Swift: `var length: Int`, `var data: UnsafePointer<CChar>!`
- DOC: "A pointer to a null-terminated string, and the length in bytes of that string." / "The length doesn't include the null terminator character."
- es_token_t: `{ size_t size; const uint8_t *data; }`. Swift: `size: Int`, `data: UnsafePointer<UInt8>!`.

---

## 11. Event structs

All DOC struct pages: `DOC:es_event_<name>_t`. Swift field types come from the DOC member pages. In Swift every `reserved[N]` field is an N-tuple of `UInt8`.

| Struct | C fields (HDR) | Swift fields (DOC) | Source |
|---|---|---|---|
| es_event_open_t | `int32_t fflag; es_file_t *_Nonnull file; uint8_t reserved[64];` | `fflag: Int32`, `file: UnsafeMutablePointer<es_file_t>` | HM:#L294-L312 |
| es_event_close_t | `bool modified; es_file_t *_Nonnull target; union { uint8_t reserved[64]; struct { bool was_mapped_writable; /* >= 6 */ }; };` | `modified: Bool`, `target: UnsafeMutablePointer<es_file_t>`, `was_mapped_writable: Bool { get set }` | HM:#L627-L653 |
| es_event_rename_t | `es_file_t *_Nonnull source; es_destination_type_t destination_type; union { es_file_t *_Nonnull existing_file; struct { es_file_t *_Nonnull dir; es_string_token_t filename; } new_path; } destination; uint8_t reserved[64];` | `source: UnsafeMutablePointer<es_file_t>`, `destination_type: es_destination_type_t`, `destination: es_event_rename_t.__Unnamed_union_destination` | HM:#L499-L529 |
| es_event_clone_t | `es_file_t *_Nonnull source; es_file_t *_Nonnull target_dir; es_string_token_t target_name; uint8_t reserved[64];` | `source`, `target_dir: UnsafeMutablePointer<es_file_t>`, `target_name: es_string_token_t` | HM:#L1038-L1051 |
| es_event_copyfile_t | `es_file_t *_Nonnull source; es_file_t *_Nullable target_file; es_file_t *_Nonnull target_dir; es_string_token_t target_name; mode_t mode; int32_t flags; uint8_t reserved[56];` | `source`, `target_file: UnsafeMutablePointer<es_file_t>?`, `target_dir`, `target_name: es_string_token_t`, `mode: mode_t`, `flags: Int32` | HM:#L1054-L1078 |
| es_event_link_t | `es_file_t *_Nonnull source; es_file_t *_Nonnull target_dir; es_string_token_t target_filename; uint8_t reserved[64];` | `source`, `target_dir`, `target_filename: es_string_token_t` | HM:#L379-L392 |
| es_event_unlink_t | `es_file_t *_Nonnull target; es_file_t *_Nonnull parent_dir; uint8_t reserved[64];` | `target`, `parent_dir` | HM:#L342-L356 |
| es_event_truncate_t | `es_file_t *_Nonnull target; uint8_t reserved[64];` | `target` | HM:#L746-L755 |
| es_event_exchangedata_t | `es_file_t *_Nonnull file1; es_file_t *_Nonnull file2; uint8_t reserved[64];` | `file1`, `file2` | HM:#L720-L731 |
| es_event_readdir_t | `es_file_t *_Nonnull target; uint8_t reserved[64];` | `target` | HM:#L1095-L1104 |
| es_event_create_t | `es_destination_type_t destination_type; union { es_file_t *_Nonnull existing_file; struct { es_file_t *_Nonnull dir; es_string_token_t filename; mode_t mode; } new_path; } destination; uint8_t reserved2[16]; union { uint8_t reserved[48]; struct { acl_t _Nullable acl; /* >= 2 */ }; };` | `destination_type`, `destination: es_event_create_t.__Unnamed_union_destination`, `acl: acl_t? { get set }` | HM:#L656-L705 |
| es_event_exec_t | `es_process_t *_Nonnull target; es_string_token_t dyld_exec_path; /* >= 7 */ union { uint8_t reserved[64]; struct { es_file_t *_Nullable script; /* >= 2 */ es_file_t *_Nonnull cwd; /* >= 3 */ int last_fd; /* >= 4 */ cpu_type_t image_cputype; /* >= 6 */ cpu_subtype_t image_cpusubtype; /* >= 6 */ }; };` | `target: UnsafeMutablePointer<es_process_t>`, `dyld_exec_path: es_string_token_t`, `script: UnsafeMutablePointer<es_file_t>? { get set }`, `cwd: UnsafeMutablePointer<es_file_t> { get set }`, `last_fd: Int32 { get set }`, `image_cputype: cpu_type_t { get set }`, `image_cpusubtype: cpu_subtype_t { get set }` | HM:#L198-L261 |
| es_event_fork_t | `es_process_t *_Nonnull child; uint8_t reserved[64];` | `child: UnsafeMutablePointer<es_process_t>` | HM:#L437-L446 |
| es_event_exit_t | `int stat; uint8_t reserved[64];` | `stat: Int32` ("This field uses the same format as the `wait(2)` system call.") | HM:#L708-L717 |

Field notes (verbatim):
- close (HDR): "`was_mapped_writable` only indicates whether the target file was mapped into writable memory or not for the lifetime of the vnode. ... The `modified` flag only reflects that a file was or was not modified by filesystem syscall. If a file was only modifed though a memory mapping this flag will be false, but was_mapped_writable will be true." DOC modified: "This value corresponds to `KAUTH_FILEOP_CLOSE_MODIFIED`."
- rename/unlink/create (HDR): "This event can fire multiple times for a single syscall, for example when the syscall has to be retried due to racing VFS operations."
- create (HDR): "If an object is being created but has not yet been created, the `destination_type` will be `ES_DESTINATION_TYPE_NEW_PATH`." / "Typically `ES_EVENT_TYPE_NOTIFY_CREATE` events are fired after the object has been created and the `destination_type` will be `ES_DESTINATION_TYPE_EXISTING_FILE`. The exception to this is for notifications that occur if an ES client responds to an `ES_EVENT_TYPE_AUTH_CREATE` event with `ES_AUTH_RESULT_DENY`."
- copyfile (HDR): "@note Not to be confused with copyfile(3). @note Prior to macOS 12.0, the copyfile syscall fired open, unlink and auth create events, but no notify create, nor write or close events." DOC target_file: "The copy file operation overwrites this file if the operation completes. If no file exists at the target location, this value is `NULL`."
- Syscall-specific events (HM:#L98-L110): "A truncate event does not indicate that a file is being truncated generally (for example by calling open(2) with the O_TRUNC flag), only specifically that truncate(2) was called. This is true for EXCHANGEDATA, CLONE, COPYFILE, SEARCHFS etc. ES events always describe specific operations, not broad concepts."
- exec (HDR): "script Script being executed by interpreter. This field is only valid if a script was executed directly and not as an argument to the interpreter (e.g. `./foo.sh` not `/bin/sh ./foo.sh`)" / "The `es_process_t` within the `es_message_t` struct (named "process") contains information about the program that calls execve(2) (or posix_spawn(2)). ... The other `es_process_t`, within the `es_event_exec_t` struct (named "target"), contains information about the program after the image has been replaced".
- link DOC naming: `target_filename` (DOC abstract says "The file name of the symbolic link". HDR: "The name of the new object linked to `source`"). Clone and copyfile use `target_name`.

### es_destination_type_t — DOC:es_destination_type_t
- `ES_DESTINATION_TYPE_EXISTING_FILE` ("The destination is an existing file."), `ES_DESTINATION_TYPE_NEW_PATH` ("The destination is a path to a new location.").
- DOC rename.destination: "If the `destination_type` is `ES_DESTINATION_TYPE_EXISTING_FILE`, the union contains an `es_file_t` member called `existing_file`. If the `destination_type` is `ES_DESTINATION_TYPE_NEW_PATH`, the union contains a `struct` called `new_path` ... an `es_file_t` called `dir` for the parent directory, and an `es_string_token_t` called `filename`."

### exec argument accessors
| Function | Avail. | Swift (DOC) | C |
|---|---|---|---|
| es_exec_arg_count — DOC:es_exec_arg_count(_:) | 10.15 | `func es_exec_arg_count(_ event: UnsafePointer<es_event_exec_t>) -> UInt32` | `extern uint32_t es_exec_arg_count(const es_event_exec_t *event);` |
| es_exec_arg — DOC:es_exec_arg(_:_:) | 10.15 | `func es_exec_arg(_ event: UnsafePointer<es_event_exec_t>, _ index: UInt32) -> es_string_token_t` | `extern es_string_token_t es_exec_arg(const es_event_exec_t *event, uint32_t index);` |
| es_exec_env_count / es_exec_env | 10.15 | `(UnsafePointer<es_event_exec_t>) -> UInt32` / `(…, _ index: UInt32) -> es_string_token_t` | |
| es_exec_fd_count / es_exec_fd | **11.0** | `-> UInt32` / `-> UnsafePointer<es_fd_t>` | |
| es_exec_entitlements — DOC:es_exec_entitlements(_:) | **27.0** | `func es_exec_entitlements(_ exec: UnsafePointer<es_event_exec_t>) -> xpc_object_t?` | `extern xpc_object_t es_exec_entitlements(const es_event_exec_t *exec);` (DOC tokens lack the space) — "The caller is responsible for releasing the returned object." |

- es_exec_arg DOC: "Attempting to read an out-of-bounds index — where `index >= es_exec_arg_count()` — results in undefined behavior." / "This function doesn't allocate memory for the returned token; it points to a string token inside of `event`. Because you don't own this memory, don't try to free it." / "[Warning] The returned pointer must not outlive the `event` parameter passed to the function".

### es_events_t union member names — DOC:es_events_t; HM:#L2468-L2583
Member names match the event names: `open`, `close`, `rename`, `clone`, `copyfile`, `link`, `unlink`, `truncate`, `exchangedata`, `readdir`, `exec`, `fork`, `exit`, `create` (and many more). Swift, e.g.: `var open: es_event_open_t { get set }`. HDR: "Events added before macOS 13.0 use structs directly." / "Events added in macOS 13.0 or later use nonnull pointers." (e.g. `es_event_authentication_t *_Nonnull authentication;`). All 14 members listed here are value structs.

---

## 12. es_event_type_t case names (HT:#L88-L294)

| Event | AUTH case | NOTIFY case | First macOS (HDR section comment) |
|---|---|---|---|
| OPEN | `ES_EVENT_TYPE_AUTH_OPEN` | `ES_EVENT_TYPE_NOTIFY_OPEN` | 10.15 |
| CLOSE | — (none exists) | `ES_EVENT_TYPE_NOTIFY_CLOSE` | 10.15 |
| RENAME | `ES_EVENT_TYPE_AUTH_RENAME` | `ES_EVENT_TYPE_NOTIFY_RENAME` | 10.15 |
| CLONE | `ES_EVENT_TYPE_AUTH_CLONE` | `ES_EVENT_TYPE_NOTIFY_CLONE` | 10.15.1 |
| COPYFILE | `ES_EVENT_TYPE_AUTH_COPYFILE` | `ES_EVENT_TYPE_NOTIFY_COPYFILE` | **12.0** (HT:#L213-L221 "The following events are available beginning in macOS 12.0") |
| LINK | `ES_EVENT_TYPE_AUTH_LINK` | `ES_EVENT_TYPE_NOTIFY_LINK` | 10.15 |
| UNLINK | `ES_EVENT_TYPE_AUTH_UNLINK` | `ES_EVENT_TYPE_NOTIFY_UNLINK` | 10.15 |
| TRUNCATE | `ES_EVENT_TYPE_AUTH_TRUNCATE` | `ES_EVENT_TYPE_NOTIFY_TRUNCATE` | 10.15 |
| EXCHANGEDATA | `ES_EVENT_TYPE_AUTH_EXCHANGEDATA` (10.15.1) | `ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA` (10.15) | |
| READDIR | `ES_EVENT_TYPE_AUTH_READDIR` | `ES_EVENT_TYPE_NOTIFY_READDIR` | 10.15.1 |
| EXEC | `ES_EVENT_TYPE_AUTH_EXEC` | `ES_EVENT_TYPE_NOTIFY_EXEC` | 10.15 |
| FORK | — | `ES_EVENT_TYPE_NOTIFY_FORK` | 10.15 |
| EXIT | — | `ES_EVENT_TYPE_NOTIFY_EXIT` | 10.15 |
| CREATE | `ES_EVENT_TYPE_AUTH_CREATE` | `ES_EVENT_TYPE_NOTIFY_CREATE` | 10.15 |

- No `AUTH_CLOSE`, `AUTH_FORK` or `AUTH_EXIT` exists in either DOC or HDR.
- All names were checked against DOC pages (e.g. DOC:es_event_type_auth_copyfile). The DOC pages give no introducedAt for enum cases.
- `ES_EVENT_TYPE_LAST` (HDR): "is not a valid event type but a convenience value for operating on the range of defined event types. This value may change between releases".
- Each DOC event-type page says, e.g. for AUTH_COPYFILE: "This identifier corresponds to the `es_events_t` union member `copyfile`, which has the type `es_event_copyfile_t`."

---

## 13. Info.plist keys, entitlement, requesting the entitlement

### com.apple.developer.endpoint-security.client — https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client
- Availability macOS 10.15. Type: Boolean.
- Abstract: "The entitlement required to monitor system events for potentially malicious activity."
- Discussion (verbatim): "You must request this entitlement from Apple. For information about how to request the entitlement, see `System Extensions and DriverKit` [https://developer.apple.com/system-extensions/]. If your app or extension lacks this requirement, `es_new_client(_:_:)` fails with the result `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`."
- https://developer.apple.com/system-extensions/ (verbatim): "Request an Entitlement — If you plan to deploy drivers built with DriverKit, allow other developers to use your system extensions, or use the EndpointSecurity API, you'll need to request an entitlement from Apple. While your request is in review, you can test system extensions on your Mac by temporarily turning off System Integrity Protection." The "Contact us" link goes to https://developer.apple.com/contact/request/system-extension/ (requires login, so its content was not read).
- Generic managed-capability process (Apple Account Help, https://developer.apple.com/help/account/capabilities/capability-requests/, verbatim excerpts): "Managed capabilities are app services that need an entitlement assigned to your account by Apple before you can enable them. ... If you are enrolled in a developer program as an organization, your Account Holder will need to submit your request for access on behalf of the team." / "Required role: Account Holder." Steps: "In Certificates, Identifiers & Profiles, click Identifiers in the sidebar. / Click the name of the identifier in the list of App IDs. / Click the Capability Requests tab. / Find the capability you want to request. / Click the Request button. / Submit the request form for the capabilty." This page does NOT name Endpoint Security specifically. Whether ES is requested through this Capability Requests tab or through the system-extension contact form is **UNVERIFIED**. The ES-specific pages point to the system-extensions page.
- [WWDC20]: "an application must have the proper EndpointSecurity entitlement. This is a restricted entitlement, and you can request a provisioning profile via the link shown here. If your application is bundled as a system extension, there is an additional entitlement required for the containing app bundle in order to install the extension."
- Sample code page (DOC:monitoring-system-events-with-endpoint-security): "Request the Endpoint Security entitlement; see `System Extensions and DriverKit`." / "Copy the app to `/Applications`, and launch it from there. You can only install System Extensions for apps launched from the `/Applications` folder."

### NSEndpointSecurityMachServiceName
- **There is no DocC page.** These 404'd: `bundleresources/information-property-list/nsendpointsecuritymachservicename` and variants. It is not listed in the Information Property List index.
- The only Apple source is [MAN] EndpointSecurity(7) (26.5 SDK, verbatim): "If the ES client is a system extension, the following optional keys can be set in the bundle's Info.plist:"
  - `NSEndpointSecurityEarlyBoot` — "Type: Boolean. If set to TRUE, the ES subsystem will hold up all mounts and third party executions (anything that is not a platform binary) until all early boot ES extensions make their first subscription."
  - `NSEndpointSecurityRebootRequired` — "Type: Boolean. If not set or set to FALSE, the new version of the extension is started immediately after terminating the old version. If set to TRUE, the new version of the extension is NOT started until the system reboots. ..."
  - `NSEndpointSecurityMachServiceName` — "Type: String. If set, this string will be the name of the MachService which can be used for XPC between the ES extension and its app. If not set, a default mach service (name: <teamID>.<bundleID>.xpc) will be provided but its usage is deprecated."
- The 10.15 man page also said: "If ES extension is combined with a Network Extension, set the NEMachServiceName key in the Info.plist." That line is gone from 11.3 onward.
- NSEndpointSecurityEarlyBoot has a DOC page (https://developer.apple.com/documentation/bundleresources/information-property-list/nsendpointsecurityearlyboot, macOS 10.15, Boolean) with an **empty abstract**.

---

## 14. es_new_client failure reasons (verbatim)

| Case | DOC abstract | DOC discussion | HDR comment (HT:#L343-L358) | Sample comment in DOC:client |
|---|---|---|---|---|
| `ES_NEW_CLIENT_RESULT_SUCCESS` | Endpoint Security successfully created the new client. | | | "Client created successfully; continue." |
| `ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT` | The attempt to create a new client contained one or more invalid arguments. | | One or more invalid arguments were provided. | "Invalid argument to es_new_client(); client or handler was null." |
| `ES_NEW_CLIENT_RESULT_ERR_INTERNAL` | Communication with the Endpoint Security subsystem failed. | | Communication with the ES subsystem failed, or other error condition. | "Failed to connect to the Endpoint Security subsystem." |
| `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` | The caller isn't properly entitled to connect to Endpoint Security. | | The caller is not properly entitled to connect. | "Extension is missing entitlement." |
| `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED` | The caller isn't permitted to connect to Endpoint Security. | "This error indicates the app lacks Transparency, Consent, and Control (TCC) approval from the user." | The caller lacks Transparency, Consent, and Control (TCC) approval from the user. | "Prompt user to perform Transparency, Consent, and Control (TCC) approval. This error is recoverable; the user can try again after approving the TCC prompt." |
| `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED` | The caller isn't running as root. | | The caller is not running as root. | "Extension is not running as root." |
| `ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS` | The caller has reached the maximum allowed number of simultaneously connected clients. | | The caller has reached the maximum number of allowed simultaneously connected clients. | "Exceeded maximum number of simultaneously-connected ES clients." |

- The DOC deadline page adds: "If your client repeatedly misses deadlines, Endpoint Security may refuse new connections from `es_new_client(_:_:)` altogether." Which result code that produces is **UNVERIFIED**.
- The maximum number of clients is **not documented** (UNVERIFIED).
- macOS 27 `es_new_descendants_client` does NOT require root or TCC (§1).

---

## Secondary corroboration: Santa (northpolesec/santa @ af35da1)

- **Retain/release wrapper:** SANTA:Source/common/es/EndpointSecurityAPI.mm#L39-L45 calls `es_retain_message(msg)` / `es_release_message(msg)`. The C++ `Message` retains in its constructor and copy constructor and releases in its destructor: SANTA:Source/common/es/Message.mm#L48-L71.
- **es_new_client** with the handler wrapped in `@autoreleasepool`: SANTA:Source/common/es/EndpointSecurityAPI.mm#L26-L37. Error strings: SANTA:Source/common/es/SNTEndpointSecurityClient.mm#L103-L108 (`ERR_NOT_PERMITTED` → "Full-disk access not granted", `ERR_NOT_PRIVILEGED` → "Not running as root", …).
- **Target-path muting + inversion:**
  - SANTA:Source/common/es/EndpointSecurityAPI.mm#L61-L75: `es_unmute_all_target_paths`, `es_muting_inverted(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) == ES_MUTE_INVERTED`, and `es_invert_muting(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH)` called **only if not already inverted** (because es_invert_muting toggles).
  - The same pattern for `ES_MUTE_INVERSION_TYPE_PROCESS` is at #L77-L87.
  - `es_mute_path(..., ES_MUTE_PATH_TYPE_TARGET_PREFIX : ES_MUTE_PATH_TYPE_TARGET_LITERAL)` and `es_mute_path_events` / `es_unmute_path` with target types: #L97-L122.
  - `enableTargetPathWatching` = unmute all target paths, then invert: SANTA:Source/common/es/SNTEndpointSecurityClient.mm#L227-L230. This matches the header advice to call `es_unmute_all_target_paths` before inverting.
  - Comment: "With inverted target path muting, only events whose target matches a muted path are delivered." SANTA:Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.mm#L486. That client then subscribes to AUTH CLONE/COPYFILE/EXCHANGEDATA/RENAME/LINK/… (#L493-L507).
- **Multi-target comment:** SANTA:Source/santad/EventProviders/SNTEndpointSecurityRecorder.mm#L163-L166: "Events like rename, clone, copyfile, exchangedata, and link have more than one target. Log the event if any target is outside FileChangesPrefixFilters and matches FileChangesRegex, so e.g. a rename from a filtered path into a watched path is still logged." This is a userspace filter, not kernel muting.
- **es_respond_flags_result:** SANTA:Source/common/es/SNTEndpointSecurityClient.mm#L271-L284. For `ES_EVENT_TYPE_AUTH_OPEN` it responds with flags `0xffffffff` (allow) or `0x0` (deny), and uses `es_respond_auth_result` for everything else. This matches the header's UINT32_MAX advice. Note: SANTA:Source/common/es/EndpointSecurityAPI.mm#L131 returns the raw `es_respond_result_t` as `bool`. Because `ES_RESPOND_RESULT_SUCCESS` is 0, success maps to `false`. This looks like a Santa quirk; don't copy it.
- **Deadline handling:** SANTA:Source/common/es/SNTEndpointSecurityClient.mm#L307-L323 `computeBudgetForDeadline`: `nanosUntilDeadline = MachTimeToNanos(deadline - currentTime)`, budget = 80% (#L78), headroom clamped to [1s, 5s] (#L81-L85). #L340-L371 does `dispatch_after(budget)` and auto-responds ALLOW, or DENY if configured fail-closed, with `cacheable:false` if the handler hasn't responded. `currentTime` is `mach_absolute_time()` (#L341). `MachTimeToNanos` uses `mach_timebase_info` (SANTA:Source/common/SystemResources.mm#L32-L52).
- `es_clear_cache` after subscribing: SANTA:Source/common/es/SNTEndpointSecurityClient.mm#L200-L210.
- Info.plist uses `NSEndpointSecurityEarlyBoot` = true (SANTA:Source/santad/Info.plist#L24-L25). The entitlement file has `com.apple.developer.endpoint-security.client` = true (SANTA:Source/santad/com.northpolesec.santa.daemon.systemextension-adhoc.entitlements). Santa does **not** set `NSEndpointSecurityMachServiceName`.

---

## UNVERIFIED (no primary-source statement found)

1. The `es_respond_*` return value when responding **after** the deadline. `ES_RESPOND_RESULT_NOT_FOUND` is plausible but undocumented.
2. AUTH_OPEN with a **non-cached** `authorized_flags` that is a strict subset of `fflag`: whether `open(2)` fails (EPERM/EACCES?) or proceeds with reduced access. Only "mask" wording and the cache-hit rule (deny unless subset) are documented.
3. The macOS release in which deadline-miss **killing** began, beyond "documented since the 10.15 SDK header". There is also a wording conflict: DOC says "may terminate"; HDR says "will be killed"; WWDC20 says "will be terminated … implicit ALLOW … not cached". macOS 27 makes it configurable, default KILL.
4. Which `es_new_client_result_t` is returned when ES "may refuse new connections" after repeated deadline misses. Also the maximum client count behind `ERR_TOO_MANY_CLIENTS`.
5. Whether the rule "only AUTH_OPEN uses `es_respond_flags_result`" (26.5 header) still holds for AUTH events new in macOS 27 (`AUTH_XPC_CONNECT`, `AUTH_BOOTSTRAP_CHECK_IN/LOOK_UP`).
6. The message `version` that gates `es_process_t.cdhash_full` (macOS 27 DOC only). The macOS release that corresponds to message version 10 (`cs_validation_category`).
7. A thread-safety statement for calling `es_respond_*`, `es_mute_*` or `es_subscribe` from arbitrary threads/queues. Only "respond out of order after retaining" is documented. The one explicit thread rule is that `es_delete_client` must be called on the thread that called `es_new_client`.
8. The exact Capability Requests path for the ES entitlement. Apple's ES docs point to https://developer.apple.com/system-extensions/ ("Request an Entitlement" → contact form). The generic Account Help "Capability Requests" page does not mention ES.
9. A DocC page for `NSEndpointSecurityMachServiceName`. None exists; the only source is the EndpointSecurity(7) man page in the SDK.
10. Per-field availability (introducedAt) for enums/structs on DocC. It is absent from the JSON. Rely on the header `message version` comments and `API_AVAILABLE` annotations instead.
