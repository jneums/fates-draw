import Result "mo:base/Result";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Debug "mo:base/Debug";
import Principal "mo:base/Principal";
import Option "mo:base/Option";
import Buffer "mo:base/Buffer";
import Base16 "mo:base16/Base16";
import Array "mo:base/Array";
import Random "mo:base/Random";
import Iter "mo:base/Iter";
import Error "mo:base/Error";
import Int "mo:base/Int";
import Time "mo:base/Time";

import HttpTypes "mo:http-types";
import Map "mo:map/Map";
import Json "mo:json";

import AuthCleanup "mo:mcp-motoko-sdk/auth/Cleanup";
import AuthState "mo:mcp-motoko-sdk/auth/State";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";

import Mcp "mo:mcp-motoko-sdk/mcp/Mcp";
import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import HttpHandler "mo:mcp-motoko-sdk/mcp/HttpHandler";
import Cleanup "mo:mcp-motoko-sdk/mcp/Cleanup";
import State "mo:mcp-motoko-sdk/mcp/State";
import Payments "mo:mcp-motoko-sdk/mcp/Payments";
import HttpAssets "mo:mcp-motoko-sdk/mcp/HttpAssets";
import Beacon "mo:mcp-motoko-sdk/mcp/Beacon";
import ApiKey "mo:mcp-motoko-sdk/auth/ApiKey";

import SrvTypes "mo:mcp-motoko-sdk/server/Types";

import IC "mo:ic";

shared ({ caller = deployer }) persistent actor class McpServer(
  args : ?{
    owner : ?Principal;
  }
) = self {

  // The canister owner, who can manage treasury funds.
  // Defaults to the deployer if not specified.
  var owner : Principal = Option.get(do ? { args!.owner! }, deployer);

  // State for certified HTTP assets (like /.well-known/...)
  var stable_http_assets : HttpAssets.StableEntries = [];
  transient let http_assets = HttpAssets.init(stable_http_assets);

  // Resource contents stored in memory for simplicity.
  // In a real application these would probably be uploaded or user generated.
  var resourceContents = [
    ("file:///README.md", "# The Fates' Draw\n\nA cryptographically secure randomness beacon on the Internet Computer."),
  ];

  // The application context that holds our state.
  var appContext : McpTypes.AppContext = State.init(resourceContents);

  // =================================================================================
  // --- OPT-IN: MONETIZATION & AUTHENTICATION ---
  // To enable paid tools, uncomment the following `authContext` initialization.
  // By default, it is `null`, and all tools are public.
  // Set the payment details in each tool definition to require payment.
  // See the README for more details.
  // =================================================================================

  transient let authContext : ?AuthTypes.AuthContext = null;

  // --- UNCOMMENT THIS BLOCK TO ENABLE AUTHENTICATION ---

  // let issuerUrl = "https://bfggx-7yaaa-aaaai-q32gq-cai.icp0.io";
  // let allowanceUrl = "https://prometheusprotocol.org/connections";
  // let requiredScopes = ["openid"];

  // //function to transform the response for jwks client
  // public query func transformJwksResponse({
  //   context : Blob;
  //   response : IC.HttpRequestResult;
  // }) : async IC.HttpRequestResult {
  //   {
  //     response with headers = []; // not intersted in the headers
  //   };
  // };

  // // Initialize the auth context with the issuer URL and required scopes.
  // transient let authContext : ?AuthTypes.AuthContext = ?AuthState.init(
  //   Principal.fromActor(self),
  //   issuerUrl,
  //   requiredScopes,
  //   transformJwksResponse,
  // );

  // --- END OF AUTHENTICATION BLOCK ---

  // =================================================================================
  // --- OPT-IN: USAGE ANALYTICS (BEACON) ---
  // To enable anonymous usage analytics, uncomment the `beaconContext` initialization.
  // This helps the Prometheus Protocol DAO understand ecosystem growth.
  // =================================================================================

  transient let beaconContext : ?Beacon.BeaconContext = null;

  // --- UNCOMMENT THIS BLOCK TO ENABLE THE BEACON ---
  /*
  let beaconCanisterId = Principal.fromText("m63pw-fqaaa-aaaai-q33pa-cai");
  transient let beaconContext : ?Beacon.BeaconContext = ?Beacon.init(
      beaconCanisterId, // Public beacon canister ID
      1 * 60 * 60, // Send a beacon every 1 hour
  );
  */
  // --- END OF BEACON BLOCK ---

  // --- Timers ---
  Cleanup.startCleanupTimer<system>(appContext);

  // The AuthCleanup timer only needs to run if authentication is enabled.
  switch (authContext) {
    case (?ctx) { AuthCleanup.startCleanupTimer<system>(ctx) };
    case (null) { Debug.print("Authentication is disabled.") };
  };

  // The Beacon timer only needs to run if the beacon is enabled.
  switch (beaconContext) {
    case (?ctx) { Beacon.startTimer<system>(ctx) };
    case (null) { Debug.print("Beacon is disabled.") };
  };

  // --- 1. DEFINE YOUR RESOURCES & TOOLS ---
  transient let resources : [McpTypes.Resource] = [
    {
      uri = "file:///README.md";
      name = "README.md";
      title = ?"About The Fates' Draw";
      description = null;
      mimeType = ?"text/markdown";
    },
  ];

  // Define the new randomness tool.
  transient let tools : [McpTypes.Tool] = [
    {
      name = "draw_randomness";
      title = ?"Draw Randomness";
      description = ?"Generates a cryptographically secure random blob of a specified length.";
      inputSchema = Json.obj([
        ("type", Json.str("object")),
        ("properties", Json.obj([("num_bytes", Json.obj([("type", Json.str("integer")), ("description", Json.str("The number of bytes of randomness to generate (1-1024)."))]))])),
        ("required", Json.arr([Json.str("num_bytes")])),
      ]);
      outputSchema = ?Json.obj([
        ("type", Json.str("object")),
        ("properties", Json.obj([("random_bytes", Json.obj([("type", Json.str("string")), ("description", Json.str("The generated random bytes, encoded as a hex string."))]))])),
        ("required", Json.arr([Json.str("random_bytes")])),
      ]);
      payment = null; // This tool is free to use.
    },
    {
      name = "coinflip";
      title = ?"Flip a Coin";
      description = ?"Simulates a fair coin toss, returning 'Heads' or 'Tails'.";
      inputSchema = Json.obj([
        ("type", Json.str("object")),
        ("properties", Json.obj([])), // No input properties
        ("required", Json.arr([])) // No required inputs
      ]);
      outputSchema = ?Json.obj([
        ("type", Json.str("object")),
        ("properties", Json.obj([("result", Json.obj([("type", Json.str("string")), ("description", Json.str("The result of the coin flip, either 'Heads' or 'Tails'."))]))])),
        ("required", Json.arr([Json.str("result")])),
      ]);
      payment = null; // This tool is also free
    },
  ];

  // --- 2. DEFINE YOUR TOOL LOGIC ---
  // The `auth` parameter will be `null` if auth is disabled or if the user is anonymous.
  // It will contain user info if auth is enabled and the user provides a valid token.
  func drawRandomnessTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : async () {
    // a. Safely parse and validate the input (no changes here).
    let num_bytes = switch (Json.getAsNat(args, "num_bytes")) {
      case (#ok(n)) { n };
      case (#err(_)) {
        return cb(#ok({ content = [#text({ text = "Invalid or missing 'num_bytes' argument." })]; isError = true; structuredContent = null }));
      };
    };

    if (num_bytes == 0 or num_bytes > 1024) {
      return cb(#ok({ content = [#text({ text = "'num_bytes' must be between 1 and 1024." })]; isError = true; structuredContent = null }));
    };

    // b. Use an `async` block to handle the asynchronous call to `Random.blob()`.
    // c. Calculate how many 32-byte blobs we need to fetch.
    // We use ceiling division: (num_bytes + 31) / 32
    let num_blobs_needed = (num_bytes + 31) / 32;
    var buffer = Buffer.Buffer<Nat8>(num_blobs_needed * 32);

    // d. Fetch the required number of random blobs in a loop.
    for (_ in Iter.range(0, num_blobs_needed - 1)) {
      let entropy_chunk : Blob = await Random.blob();
      for (byte in entropy_chunk.vals()) {
        buffer.add(byte);
      };
    };

    // e. Trim the buffer to the exact requested size.
    let final_blob = Blob.fromArray(Array.subArray(Buffer.toArray(buffer), 0, num_bytes));

    // f. Format the output (no changes here).
    let hex_string = Base16.encode(final_blob);
    let structuredPayload = Json.obj([("random_bytes", Json.str(hex_string))]);
    let stringified = Json.stringify(structuredPayload, null);

    // g. Return the successful result via the callback.
    cb(#ok({ content = [#text({ text = stringified })]; isError = false; structuredContent = ?structuredPayload }));
  };

  // The implementation for the new coinflip tool.
  func coinflipTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : async () {
    try {
      // 1. Fetch a fresh 32-byte blob of secure entropy from the IC.
      let entropy : Blob = await Random.blob();

      // 2. Create a `Finite` randomness source from the entropy.
      let random = Random.Finite(entropy);

      // 3. Use the `coin()` method to get a random boolean (?Bool).
      switch (random.coin()) {
        case (?was_heads) {
          // The flip was successful.
          let result_text = if (was_heads) { "Heads" } else { "Tails" };

          // 4. Format the output to match the schema.
          let structuredPayload = Json.obj([("result", Json.str(result_text))]);
          let stringified = Json.stringify(structuredPayload, null);

          // 5. Return the successful result.
          cb(#ok({ content = [#text({ text = stringified })]; isError = false; structuredContent = ?structuredPayload }));
        };
        case (null) {
          // This is extremely unlikely with a 32-byte entropy source, but we handle it for safety.
          cb(#ok({ content = [#text({ text = "Failed to draw randomness from entropy source." })]; isError = true; structuredContent = null }));
        };
      };
    } catch (e) {
      // Handle any unexpected errors during the async call.
      let error_msg = "An unexpected error occurred: " # Error.message(e);
      cb(#ok({ content = [#text({ text = error_msg })]; isError = true; structuredContent = null }));
    };
  };

  // --- 3. CONFIGURE THE SDK ---
  transient let mcpConfig : McpTypes.McpConfig = {
    self = Principal.fromActor(self);
    allowanceUrl = null;
    serverInfo = {
      name = "the-fates-draw";
      title = "The Fates' Draw";
      version = "1.1.2";
    };
    resources = resources;
    resourceReader = func(uri) {
      Map.get(appContext.resourceContents, Map.thash, uri);
    };
    tools = tools;
    toolImplementations = [
      ("draw_randomness", drawRandomnessTool), // Map the tool name to its implementation
      ("coinflip", coinflipTool),
    ];
    beacon = beaconContext;
  };

  // --- 4. CREATE THE SERVER LOGIC ---
  transient let mcpServer = Mcp.createServer(mcpConfig);

  // --- PUBLIC ENTRY POINTS ---

  /// Get the current owner of the canister.
  public query func get_owner() : async Principal { return owner };

  /// Set a new owner for the canister. Only the current owner can call this.
  public shared ({ caller }) func set_owner(new_owner : Principal) : async Result.Result<(), Payments.TreasuryError> {
    if (caller != owner) { return #err(#NotOwner) };
    owner := new_owner;
    return #ok(());
  };

  /// Get the canister's balance of a specific ICRC-1 token.
  public shared func get_treasury_balance(ledger_id : Principal) : async Nat {
    return await Payments.get_treasury_balance(Principal.fromActor(self), ledger_id);
  };

  /// Withdraw tokens from the canister's treasury to a specified destination.
  public shared ({ caller }) func withdraw(
    ledger_id : Principal,
    amount : Nat,
    destination : Payments.Destination,
  ) : async Result.Result<Nat, Payments.TreasuryError> {
    return await Payments.withdraw(
      caller,
      owner,
      ledger_id,
      amount,
      destination,
    );
  };

  // Helper to create the HTTP context for each request.
  private func _create_http_context() : HttpHandler.Context {
    return {
      self = Principal.fromActor(self);
      active_streams = appContext.activeStreams;
      mcp_server = mcpServer;
      streaming_callback = http_request_streaming_callback;
      // This passes the optional auth context to the handler.
      // If it's `null`, the handler will skip all auth checks.
      auth = authContext;
      http_asset_cache = ?http_assets.cache;
      mcp_path = ?"/mcp";
    };
  };

  /// Handle incoming HTTP requests.
  public query func http_request(req : SrvTypes.HttpRequest) : async SrvTypes.HttpResponse {
    let ctx : HttpHandler.Context = _create_http_context();
    // Ask the SDK to handle the request
    switch (HttpHandler.http_request(ctx, req)) {
      case (?mcpResponse) {
        // The SDK handled it, so we return its response.
        return mcpResponse;
      };
      case (null) {
        // The SDK ignored it. Now we can handle our own custom routes.
        if (req.url == "/") {
          // e.g., Serve a frontend asset
          return {
            status_code = 200;
            headers = [("Content-Type", "text/html")];
            body = Text.encodeUtf8("<h1>My Canister Frontend</h1>");
            upgrade = null;
            streaming_strategy = null;
          };
        } else {
          // Return a 404 for any other unhandled routes.
          return {
            status_code = 404;
            headers = [];
            body = Blob.fromArray([]);
            upgrade = null;
            streaming_strategy = null;
          };
        };
      };
    };
  };

  /// Handle incoming HTTP requests that modify state (e.g., POST).
  public shared func http_request_update(req : SrvTypes.HttpRequest) : async SrvTypes.HttpResponse {
    let ctx : HttpHandler.Context = _create_http_context();

    // Ask the SDK to handle the request
    let mcpResponse = await HttpHandler.http_request_update(ctx, req);

    switch (mcpResponse) {
      case (?res) {
        // The SDK handled it.
        return res;
      };
      case (null) {
        // The SDK ignored it. Handle custom update calls here.
        return {
          status_code = 404;
          headers = [];
          body = Blob.fromArray([]);
          upgrade = null;
          streaming_strategy = null;
        };
      };
    };
  };

  /// Handle streaming callbacks for large HTTP responses.
  public query func http_request_streaming_callback(token : HttpTypes.StreamingToken) : async ?HttpTypes.StreamingCallbackResponse {
    let ctx : HttpHandler.Context = _create_http_context();
    return HttpHandler.http_request_streaming_callback(ctx, token);
  };

  // --- CANISTER LIFECYCLE MANAGEMENT ---

  system func preupgrade() {
    stable_http_assets := HttpAssets.preupgrade(http_assets);
  };

  system func postupgrade() {
    HttpAssets.postupgrade(http_assets);
  };

  /**
   * Creates a new API key. This API key is linked to the caller's principal.
   * @param name A human-readable name for the key.
   * @returns The raw, unhashed API key. THIS IS THE ONLY TIME IT WILL BE VISIBLE.
   */
  public shared (msg) func create_my_api_key(name : Text, scopes : [Text]) : async Text {
    switch (authContext) {
      case (null) {
        Debug.trap("Authentication is not enabled on this canister.");
      };
      case (?ctx) {
        return await ApiKey.create_my_api_key(
          ctx,
          msg.caller,
          name,
          scopes,
        );
      };
    };
  };

  /** Revoke (delete) an API key owned by the caller.
   * @param key_id The ID of the key to revoke.
   * @returns True if the key was found and revoked, false otherwise.
   */
  public shared (msg) func revoke_my_api_key(key_id : Text) : async () {
    switch (authContext) {
      case (null) {
        Debug.trap("Authentication is not enabled on this canister.");
      };
      case (?ctx) {
        return ApiKey.revoke_my_api_key(ctx, msg.caller, key_id);
      };
    };
  };

  /** List all API keys owned by the caller.
   * @returns A list of API key metadata (but not the raw keys).
   */
  public query (msg) func list_my_api_keys() : async [AuthTypes.ApiKeyMetadata] {
    switch (authContext) {
      case (null) {
        Debug.trap("Authentication is not enabled on this canister.");
      };
      case (?ctx) {
        return ApiKey.list_my_api_keys(ctx, msg.caller);
      };
    };
  };

  /// (5.1) Upgrade finished stub
  public type UpgradeFinishedResult = {
    #InProgress : Nat;
    #Failed : (Nat, Text);
    #Success : Nat;
  };
  private func natNow() : Nat {
    return Int.abs(Time.now());
  };
  public func icrc120_upgrade_finished() : async UpgradeFinishedResult {
    #Success(natNow());
  };
};
