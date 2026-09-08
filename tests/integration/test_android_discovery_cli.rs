use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn write_test_apk(path: &std::path::Path, split: bool) {
    let file = std::fs::File::create(path).expect("create apk");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    let manifest = if split {
        r#"<manifest package="com.example.feature"><application /></manifest>"#
    } else {
        r#"
        <manifest package="com.example.app">
          <application>
            <activity android:name=".MainActivity" android:exported="true" />
            <service android:name=".SyncService" android:exported="false" />
            <provider android:name=".FilesProvider" android:permission="com.example.READ" />
          </application>
        </manifest>
        "#
    };

    zip.start_file("AndroidManifest.xml", opts)
        .expect("manifest entry");
    use std::io::Write as _;
    zip.write_all(manifest.as_bytes()).expect("manifest bytes");

    if !split {
        zip.start_file("classes.dex", opts).expect("classes.dex");
        zip.write_all(b"dex").expect("dex bytes");
        zip.start_file("classes2.dex", opts).expect("classes2.dex");
        zip.write_all(b"dex2").expect("dex bytes");
        zip.start_file("lib/arm64-v8a/libfoo.so", opts)
            .expect("libfoo");
        zip.write_all(b"so").expect("lib bytes");
        zip.start_file("res/xml/file_paths.xml", opts)
            .expect("file_paths");
        zip.write_all(b"<paths/>").expect("xml bytes");
        zip.start_file("assets/index.html", opts).expect("index");
        zip.write_all(b"<html></html>").expect("asset bytes");
        zip.start_file("assets/deep_link_router.json", opts)
            .expect("router asset");
        zip.write_all(br#"{"route":"/x"}"#).expect("router bytes");
    } else {
        zip.start_file("classes3.dex", opts).expect("classes3.dex");
        zip.write_all(b"dex3").expect("dex bytes");
    }

    zip.finish().expect("finish zip");
}

fn write_surface_manifest_apk(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create apk");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    let manifest = r#"
    <manifest package="com.example.surface">
      <application>
        <activity android:name=".DeepLinkActivity" android:exported="true">
          <intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.DEFAULT" />
            <category android:name="android.intent.category.BROWSABLE" />
            <data android:scheme="https" android:host="example.app" android:pathPrefix="/devices/" />
          </intent-filter>
        </activity>
        <service android:name=".PublicService" android:exported="true" />
        <provider
          android:name=".FilesProvider"
          android:authorities="com.example.surface.files"
          android:exported="true"
          android:grantUriPermissions="true" />
      </application>
    </manifest>
    "#;

    zip.start_file("AndroidManifest.xml", opts)
        .expect("manifest entry");
    use std::io::Write as _;
    zip.write_all(manifest.as_bytes()).expect("manifest bytes");
    zip.start_file("classes.dex", opts).expect("classes.dex");
    zip.write_all(b"dex").expect("dex bytes");
    zip.finish().expect("finish zip");
}

fn write_manifest_apk_with_package(path: &std::path::Path, package_name: &str) {
    let file = std::fs::File::create(path).expect("create apk");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    let manifest = format!(
        r#"
    <manifest package="{package_name}">
      <application>
        <activity android:name=".DeepLinkActivity" android:exported="true" />
      </application>
    </manifest>
    "#
    );

    zip.start_file("AndroidManifest.xml", opts)
        .expect("manifest entry");
    use std::io::Write as _;
    zip.write_all(manifest.as_bytes()).expect("manifest bytes");
    zip.start_file("classes.dex", opts).expect("classes.dex");
    zip.write_all(b"dex").expect("dex bytes");
    zip.finish().expect("finish zip");
}

fn write_semantic_bundle(path: &std::path::Path, package_name: &str) {
    let bundle = serde_json::json!({
        "bundle_version": "android-semantic/v1alpha1",
        "target": {
            "application_id": package_name,
            "package_name": package_name,
            "version_code": "42",
            "version_name": "1.0",
            "split_names": ["base", "feature.camera"]
        },
        "extractor": {
            "extractor_id": "jadx-recon",
            "extractor_version": "0.1.0",
            "input_kind": "jadx-tree",
            "generated_at_utc": "2026-04-06T12:00:00Z",
            "degraded": false,
            "notes": ["semantic extraction complete"]
        },
        "facts": [
            {
                "fact_id": "fact-observed-1",
                "kind": "control-surface.router-dispatch",
                "subject": "Lcom/example/Router;->dispatch(Ljava/lang/String;)V",
                "support_level": "Observed",
                "provenance": [
                    {
                        "origin": "jadx",
                        "artifact": "sources/com/example/Router.java",
                        "location": "dispatch:41",
                        "detail": "switch over route token"
                    }
                ],
                "attributes": {
                    "route_source": "intent-extra"
                }
            },
            {
                "fact_id": "fact-inferred-1",
                "kind": "trust-boundary.deep-link-to-router",
                "subject": "route://deeplink",
                "support_level": "Inferred",
                "provenance": [
                    {
                        "origin": "correlator",
                        "artifact": "deeplink-routing",
                        "detail": "manifest filter aligns with router sink"
                    }
                ],
                "attributes": {}
            }
        ],
        "symbol_identities": [
            {
                "symbol_id": "sym-router-dispatch",
                "language": "java",
                "kind": "method",
                "qualified_name": "com.example.Router.dispatch",
                "descriptor": "(Ljava/lang/String;)V",
                "aliases": ["Lcom/example/Router;->dispatch(Ljava/lang/String;)V"]
            },
            {
                "symbol_id": "sym-js-bridge",
                "language": "java",
                "kind": "method",
                "qualified_name": "com.example.WebBridge.webSendCmdRes",
                "aliases": []
            }
        ],
        "control_surfaces": [
            {
                "surface_id": "control-router-dispatch",
                "kind": "router-dispatch",
                "entry_symbol": "sym-router-dispatch",
                "exported_component": "com.example.DeepLinkActivity",
                "trigger": "android.intent.action.VIEW",
                "notes": ["dispatches untrusted route material"]
            },
            {
                "surface_id": "control-js-bridge",
                "kind": "javascript-interface-method",
                "entry_symbol": "sym-js-bridge",
                "trigger": "webSendCmdRes(String)",
                "notes": ["command-dispatch", "JavascriptInterface method"]
            }
        ],
        "transport_surfaces": [
            {
                "surface_id": "transport-deeplink-intent",
                "kind": "intent-parse",
                "source": "external-deeplink",
                "sink": "control-router-dispatch",
                "carrier": "android.net.Uri",
                "notes": ["URI path becomes route token"]
            }
        ],
        "trust_boundaries": [
            {
                "boundary_id": "boundary-deeplink-router",
                "kind": "deep-link-to-internal-router",
                "from_zone": "external-caller",
                "to_zone": "app-router",
                "guard": "route allowlist",
                "notes": ["allowlist not confirmed at extraction time"]
            }
        ],
        "resources": [
            {
                "resource_id": "resource-network-config",
                "kind": "xml-network-security-config",
                "path": "res/xml/network_security_config.xml",
                "qualifiers": [],
                "notes": ["debug-overrides absent"]
            }
        ],
        "native_semantics": [
            {
                "native_id": "native-jni-dispatch",
                "kind": "jni-registration",
                "library_name": "librouter.so",
                "symbol_name": "Java_com_example_Router_nativeDispatch",
                "linked_symbol_id": "sym-router-dispatch",
                "notes": ["Java entrypoint crosses into native parser"]
            }
        ],
        "subsystems": [
            {
                "subsystem_id": "subsystem-router",
                "kind": "router",
                "support_level": "Observed",
                "package_prefixes": ["com.example"],
                "symbol_ids": ["sym-router-dispatch"],
                "control_surface_ids": ["control-router-dispatch"],
                "transport_surface_ids": ["transport-deeplink-intent"],
                "trust_boundary_ids": ["boundary-deeplink-router"],
                "native_ids": ["native-jni-dispatch"],
                "fact_ids": ["fact-observed-1"],
                "rationale": "router symbols and deeplink handling cluster together",
                "notes": ["synthetic subsystem fixture"]
            }
        ],
        "correlations": [
            {
                "correlation_id": "corr-router-native",
                "kind": "symbol-to-native",
                "members": ["sym-router-dispatch", "native-jni-dispatch"],
                "support_level": "Observed",
                "rationale": "JNI name and descriptor match"
            }
        ],
        "revelations": [
            {
                "revelation_id": "rev-router-dispatch-surface",
                "kind": "router dispatch surface",
                "support_level": "Observed",
                "members": ["sym-router-dispatch", "control-router-dispatch"],
                "subsystem_ids": ["subsystem-router"],
                "rationale": "switch over route token"
            },
            {
                "revelation_id": "rev-deeplink-trust-boundary",
                "kind": "deep-link trust boundary",
                "support_level": "Inferred",
                "members": ["transport-deeplink-intent", "boundary-deeplink-router"],
                "subsystem_ids": ["subsystem-router"],
                "rationale": "manifest filter aligns with router sink"
            }
        ],
        "warnings": ["no kotlin metadata available"]
    });

    std::fs::write(
        path,
        serde_json::to_vec_pretty(&bundle).expect("serialize bundle"),
    )
    .expect("write semantic bundle");
}

fn write_jadx_router_tree(root: &Path) {
    let sources = root.join("sources/com/example");
    fs::create_dir_all(&sources).expect("sources dir");
    fs::write(
        sources.join("DeepLinkActivity.java"),
        r#"
package com.example;

import android.content.Intent;
import android.net.Uri;

public class DeepLinkActivity {
    public void onCreate(Intent intent) {
        Uri uri = intent.getData();
        new Router().dispatch(uri.toString());
    }
}
"#,
    )
    .expect("write DeepLinkActivity");
    fs::write(
        sources.join("Router.java"),
        r#"
package com.example;

public class Router {
    public void dispatch(String route) {
        String endpoint = "/api/v1/devices/{sn}";
        String auth = "Authorization";
        String mqtt = "mqtt://broker/devices/{sn}";
    }
}
"#,
    )
    .expect("write Router");
}

fn write_jadx_guarded_router_tree(root: &Path) {
    let sources = root.join("sources/com/example");
    fs::create_dir_all(&sources).expect("sources dir");
    fs::write(
        sources.join("DeepLinkActivity.java"),
        r#"
package com.example;

import android.content.Intent;
import android.net.Uri;

public class DeepLinkActivity {
    public void onCreate(Intent intent) {
        String caller = getCallingPackage();
        Uri uri = intent.getData();
        new Router().dispatch(uri.toString());
    }
}
"#,
    )
    .expect("write DeepLinkActivity");
    fs::write(
        sources.join("Router.java"),
        r#"
package com.example;

public class Router {
    public void dispatch(String route) {
        String endpoint = "/api/v1/devices/{sn}";
    }
}
"#,
    )
    .expect("write Router");
}

fn write_jadx_guarded_router_false_positive_tree(root: &Path) {
    let sources = root.join("sources/com/example");
    fs::create_dir_all(&sources).expect("sources dir");
    fs::write(
        sources.join("DeepLinkActivity.java"),
        r#"
package com.example;

import android.content.Intent;
import android.net.Uri;

public class DeepLinkActivity {
    public void onCreate(Intent intent) {
        Uri uri = intent.getData();
        new Router().dispatch(uri.toString());
    }
}
"#,
    )
    .expect("write DeepLinkActivity");
    fs::write(
        sources.join("Router.java"),
        r#"
package com.example;

public class Router {
    public void dispatch(String route) {
        String endpoint = "/api/v1/devices/{sn}";
    }
}
"#,
    )
    .expect("write Router");
    fs::write(
        sources.join("UnrelatedGuard.java"),
        r#"
package com.example;

public class UnrelatedGuard {
    public int guard() {
        return getCallingUid();
    }
}
"#,
    )
    .expect("write UnrelatedGuard");
}

fn write_jadx_sparse_tree(root: &Path) {
    let sources = root.join("sources/a/b");
    fs::create_dir_all(&sources).expect("sources dir");
    fs::write(
        sources.join("Entry.java"),
        r#"
package a.b;

import android.app.PendingIntent;
import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;

public class Entry {
    public void trigger(Intent intent, PendingIntent pi, ContentResolver resolver) throws Exception {
        startActivity(intent);
        resolver.query(Uri.parse("content://com.example.surface.files/device"), null, null, null, null);
        PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_MUTABLE);
        Runtime.getRuntime().exec("logcat");
    }
}
"#,
    )
    .expect("write Entry");
}

fn write_jadx_binder_placeholder_tree(root: &Path) {
    let sources = root.join("sources/com/example/binder");
    fs::create_dir_all(&sources).expect("binder dir");
    fs::write(
        sources.join("BridgeHints.java"),
        r#"
package com.example.binder;

public class BridgeHints {
    static {
        System.loadLibrary("native");
    }

    public void handleBinderParcel(byte[] blob, int length) {
        String binder = "binder";
        String parcel = "parcel";
        String size = "size";
        String copy = "copy";
    }
}
"#,
    )
    .expect("write BridgeHints");
}

fn write_jadx_binder_resolved_tree(root: &Path) {
    let sources = root.join("sources/com/example/binder");
    fs::create_dir_all(&sources).expect("binder dir");
    fs::write(
        sources.join("BlobBridge.java"),
        r#"
package com.example.binder;

public class BlobBridge {
    static {
        System.loadLibrary("blob");
    }

    public void onTransact(byte[] blob, int length) {
        String binder = "binder";
        String parcel = "parcel";
        String size = "size";
        String copy = "copy";
    }
}
"#,
    )
    .expect("write BlobBridge");
}

fn write_jadx_third_party_noise_tree(root: &Path) {
    let room_dir = root.join("sources/androidx/room");
    let ta_dir = root.join("sources/com/ta/a/c");
    let iflytek_dir = root.join("sources/com/iflytek/speech");
    fs::create_dir_all(&room_dir).expect("room dir");
    fs::create_dir_all(&ta_dir).expect("ta dir");
    fs::create_dir_all(&iflytek_dir).expect("iflytek dir");

    fs::write(
        room_dir.join("Room.java"),
        r#"
package androidx.room;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.Uri;

public class Room {
    public void dispatch(Intent intent) {
        PendingIntent.getActivity(null, 0, intent, PendingIntent.FLAG_MUTABLE);
        startActivity(intent);
        intent.getData();
        intent.getDataString();
        String route = "router";
    }
}
"#,
    )
    .expect("write Room");

    fs::write(
        ta_dir.join("f.java"),
        r#"
package com.ta.a.c;

import android.content.Intent;

public class f {
    public void dispatch(Intent intent) {
        intent.getDataString();
        String marker = "router";
    }
}
"#,
    )
    .expect("write router noise");

    fs::write(
        iflytek_dir.join("Default.java"),
        r#"
package com.iflytek.speech;

public class Default {
    static {
        System.loadLibrary("speech");
    }

    public void onTransact(byte[] blob, int length) {
        String binder = "binder";
        String parcel = "parcel";
        String size = "size";
        String copy = "copy";
    }
}
"#,
    )
    .expect("write binder noise");
}

fn write_jadx_unitree_owned_webview_tree(root: &Path) {
    let agentweb_dir = root.join("sources/com/just/agentweb");
    let app_dir = root.join("sources/com/unitree/doggo2/ui/activity/web");
    fs::create_dir_all(&agentweb_dir).expect("agentweb dir");
    fs::create_dir_all(&app_dir).expect("app dir");

    fs::write(
        agentweb_dir.join("UrlLoaderImpl.java"),
        r#"
package com.just.agentweb;

public class UrlLoaderImpl {
    public void loadUrl(String url) {
        String webView = "webview";
        addJavascriptInterface();
    }

    public void addJavascriptInterface() {}
}
"#,
    )
    .expect("write agentweb");

    fs::write(
        app_dir.join("WebActivity.java"),
        r#"
package com.unitree.doggo2.ui.activity.web;

import android.webkit.WebView;

public class WebActivity {
    public void loadUrl(WebView webView, String url) {
        webView.loadUrl(url);
        addJavascriptInterface();
    }

    public void addJavascriptInterface() {}
}
"#,
    )
    .expect("write app webview");
}

fn write_jadx_unitree_control_plane_tree(root: &Path) {
    let web_dir = root.join("sources/com/unitree/doggo2/ui/fragment/web");
    let webrtc_dir = root.join("sources/com/unitree/webrtc/data");
    let ble_dir = root.join("sources/com/unitree/lib_ble/ui");
    let login_dir = root.join("sources/com/unitree/login/data/api");
    let login_model_dir = root.join("sources/com/unitree/login/data");
    fs::create_dir_all(&web_dir).expect("web dir");
    fs::create_dir_all(&webrtc_dir).expect("webrtc dir");
    fs::create_dir_all(&ble_dir).expect("ble dir");
    fs::create_dir_all(&login_dir).expect("login dir");
    fs::create_dir_all(&login_model_dir).expect("login model dir");

    fs::write(
        web_dir.join("AndroidInterface.java"),
        r#"
package com.unitree.doggo2.ui.fragment.web;

import android.webkit.JavascriptInterface;
import com.unitree.webrtc.data.SendGo2Req;
import com.unitree.webrtc.data.DogOfferBean;

public class AndroidInterface {
    @JavascriptInterface
    public void webSendRTCSessionDescription(String sdp) {
        DogOfferBean bean = new DogOfferBean();
        bean.token = "session-token";
        bean.sdp = sdp;
        bean.type = "offer";
        EventBus.getDefault().post(bean);
    }

    @JavascriptInterface
    public void webSendSportState() {
        SendGo2Req req = new SendGo2Req();
        req.topic = "rt/api/sport/request";
        req.api_id = "ACTION_HAND_SHAKE";
        req.id = "sport-1";
    }

    @JavascriptInterface
    public void webSendCmdRes(String payload) {
        SendGo2Req req = new SendGo2Req();
        req.topic = "rt/api/sport/request";
        req.api_id = "ACTION_HAND_SHAKE";
        req.id = payload;
        EventBus.getDefault().post(req);
    }

    @JavascriptInterface
    public void webSendHttpRequest(String body) {
        String url = "https://api.example/device";
        HttpClient.execute(url, body);
    }

    @JavascriptInterface
    public void webSaveProgramData(String json) {
        FileWriter writer = new FileWriter("/tmp/program.json");
        writer.write(json);
    }

    @JavascriptInterface
    public void backToApp(String ignored) {
        String route = "return-to-app";
    }

    @JavascriptInterface
    public void webReqTurnServerInfo() {
        String turn = "turn://robot.example";
    }
}
"#,
    )
    .expect("write AndroidInterface");

    fs::write(
        webrtc_dir.join("SendGo2Req.java"),
        r#"
package com.unitree.webrtc.data;

public class SendGo2Req {
    public String topic;
    public String api_id;
    public String id;
    public String data;
    public int priority;
}
"#,
    )
    .expect("write SendGo2Req");

    fs::write(
        webrtc_dir.join("DogOfferBean.java"),
        r#"
package com.unitree.webrtc.data;

public class DogOfferBean {
    public String sdp;
    public String type;
    public String token;
}
"#,
    )
    .expect("write DogOfferBean");

    fs::write(
        ble_dir.join("BluetoothService.java"),
        r#"
package com.unitree.lib_ble.ui;

public class BluetoothService {
    public void connectBluetooth() {
        String serviceUuid = "UUID_SERVER";
        String notifyUuid = "UUID_NOTI";
    }

    public void sendData(byte[] bytes) {
        AESUtil.INSTANCE.decrypt(bytes);
        String serial = "SerialNumberResultEvent";
        String state = "BleConnectChangeEvent";
    }
}
"#,
    )
    .expect("write BluetoothService");

    fs::write(
        login_dir.join("LoginApi.java"),
        r#"
package com.unitree.login.data.api;

public interface LoginApi {
    String TOKEN = "oauth/token";
    String BIND = "oauth/bind";
    String BIND_ACCOUNTS = "oauth/bind/accounts";
    String UNBIND = "oauth/unbind";
    String DEVICE_ADDRESS = "DEVICE_ADDRESS";
}
"#,
    )
    .expect("write LoginApi");

    fs::write(
        login_model_dir.join("LoginDataBean.java"),
        r#"
package com.unitree.login.data;

public class LoginDataBean {
    public String accessToken;
    public String refreshToken;
    public String user;
}
"#,
    )
    .expect("write LoginDataBean");
}

fn write_jadx_unitree_transport_truth_tree(root: &Path) {
    write_jadx_unitree_control_plane_tree(root);
    let misc_dir = root.join("sources/com/unitree/doggo2/debug");
    let proto_dir = root.join("sources/kotlin/reflect/jvm/internal/impl/serialization");
    fs::create_dir_all(&misc_dir).expect("misc dir");
    fs::create_dir_all(&proto_dir).expect("proto dir");

    fs::write(
        misc_dir.join("TransportTruthDebug.java"),
        r#"
package com.unitree.doggo2.debug;

public class TransportTruthDebug {
    public void logMarkers() {
        String grpcStatusLabel = "grpc status pending";
        String weaveStatusLabel = "weave status pending";
        String commandTopic = "topic";
        String routingTopic = "rt/api/sport/request";
    }
}
"#,
    )
    .expect("write transport truth debug");

    fs::write(
        proto_dir.join("SerializerExtensionProtocol.java"),
        r#"
package kotlin.reflect.jvm.internal.impl.serialization;

import kotlin.reflect.jvm.internal.impl.protobuf.GeneratedMessageLite;

public class SerializerExtensionProtocol {
    private final GeneratedMessageLite.GeneratedExtension<?, ?> extension;

    public SerializerExtensionProtocol(GeneratedMessageLite.GeneratedExtension<?, ?> extension) {
        this.extension = extension;
    }
}
"#,
    )
    .expect("write serializer extension protocol");
}

fn write_jadx_http_api_tree(root: &Path) {
    let login_dir = root.join("sources/com/example/login/data/api");
    let app_dir = root.join("sources/com/example/app/data/api");
    let rtc_dir = root.join("sources/com/example/webrtc/data/api");
    let net_dir = root.join("sources/com/example/net");
    fs::create_dir_all(&login_dir).expect("login dir");
    fs::create_dir_all(&app_dir).expect("app dir");
    fs::create_dir_all(&rtc_dir).expect("rtc dir");
    fs::create_dir_all(&net_dir).expect("net dir");

    fs::write(
        login_dir.join("LoginApi.java"),
        r#"
package com.example.login.data.api;

public interface LoginApi {
    @POST("oauth/token")
    Call<TokenResponse> token();

    @POST("oauth/bind")
    Call<BindResponse> bind();

    @GET("oauth/bind/accounts")
    Call<AccountList> accounts();
}
"#,
    )
    .expect("write LoginApi");

    fs::write(
        app_dir.join("AppApi.java"),
        r#"
package com.example.app.data.api;

public interface AppApi {
    @POST("device/bind")
    Call<Void> bindDevice();

    @POST("firmware/package/download")
    Call<Void> downloadFirmware();
}
"#,
    )
    .expect("write AppApi");

    fs::write(
        rtc_dir.join("WebRTCApi.java"),
        r#"
package com.example.webrtc.data.api;

public interface WebRTCApi {
    @POST("webrtc/connect")
    Call<Void> connect();

    @POST("{path}")
    Call<Void> dynamic(@Path("path") String path);
}
"#,
    )
    .expect("write WebRTCApi");

    fs::write(
        net_dir.join("AuthInterceptor.java"),
        r#"
package com.example.net;

public final class AuthInterceptor {
    public Request intercept(Request request, String token, String appSign, String nonce) {
        Request.Builder builder = request.newBuilder();
        builder.header("AppSign", appSign);
        builder.addHeader("Token", token);
        builder.header("AppNonce", nonce);
        return builder.build();
    }
}
"#,
    )
    .expect("write AuthInterceptor");
}

fn write_jadx_command_catalog_tree(root: &Path) {
    let webrtc_dir = root.join("sources/com/example/webrtc/data");
    fs::create_dir_all(&webrtc_dir).expect("webrtc dir");

    fs::write(
        webrtc_dir.join("DogApiId.java"),
        r#"
package com.example.webrtc.data;

public enum DogApiId {
    BASH_RUNNER,
    CLEAR_DATA,
    PROGRAM_ACTUATOR_SET
}
"#,
    )
    .expect("write DogApiId");

    fs::write(
        webrtc_dir.join("BaseRunner.java"),
        r#"
package com.example.webrtc.data;

public enum BaseRunner {
    clear_data,
    upload_program,
    bash_runner
}
"#,
    )
    .expect("write BaseRunner");

    fs::write(
        webrtc_dir.join("SendGo2Req.java"),
        r#"
package com.example.webrtc.data;

public class SendGo2Req {
    public String topic;
    public String api_id;
    public String id;
    public String data;
    public int priority;
}
"#,
    )
    .expect("write SendGo2Req");
}

fn write_jadx_ble_security_tree(root: &Path) {
    let ble_dir = root.join("sources/com/example/ble");
    fs::create_dir_all(&ble_dir).expect("ble dir");

    fs::write(
        ble_dir.join("BluetoothService.java"),
        r#"
package com.example.ble;

import android.bluetooth.BluetoothAdapter;

public class BluetoothService {
    public static final String UUID_SERVER = "0000fff1-0000-1000-8000-00805f9b34fb";
    public static final String UUID_NOTI = "0000fff4-0000-1000-8000-00805f9b34fb";

    public void connectBluetooth(BluetoothAdapter adapter) {
        String state = "local-device-bootstrap";
    }

    public void exchangeSessionKey(byte[] wrappedKey) {
        String sessionKey = "session_key";
        AESUtil.decrypt(wrappedKey);
    }
}
"#,
    )
    .expect("write BluetoothService");

    fs::write(
        ble_dir.join("AESUtil.java"),
        r#"
package com.example.ble;

import javax.crypto.Cipher;

public final class AESUtil {
    public static byte[] decrypt(byte[] wrappedKey) {
        Cipher.getInstance("AES/CFB128/NoPadding");
        Cipher.getInstance("AES/GCM/NoPadding");
        return wrappedKey;
    }
}
"#,
    )
    .expect("write AESUtil");
}

fn write_jadx_unitree_chain_tree(root: &Path) {
    write_jadx_unitree_control_plane_tree(root);
    let webrtc_dir = root.join("sources/com/unitree/webrtc/data");
    fs::create_dir_all(&webrtc_dir).expect("webrtc dir");

    fs::write(
        webrtc_dir.join("DogApiId.java"),
        r#"
package com.unitree.webrtc.data;

public enum DogApiId {
    BASH_RUNNER,
    PROGRAM_ACTUATOR_SET
}
"#,
    )
    .expect("write DogApiId");

    fs::write(
        webrtc_dir.join("BaseRunner.java"),
        r#"
package com.unitree.webrtc.data;

public enum BaseRunner {
    bash_runner,
    program_actuator_set
}
"#,
    )
    .expect("write BaseRunner");
}

fn write_jadx_mesh_protocol_tree(root: &Path) {
    let weave_dir = root.join("sources/com/example/weave/DeviceManager");
    let grpc_dir = root.join("sources/com/example/media/transport/common");
    fs::create_dir_all(&weave_dir).expect("weave dir");
    fs::create_dir_all(&grpc_dir).expect("grpc dir");
    fs::write(
        weave_dir.join("WeaveDeviceManager.java"),
        r#"
package com.example.weave.DeviceManager;

import io.grpc.Status;
import org.webrtc.PeerConnection;

public class WeaveDeviceManager {
    static {
        System.loadLibrary("WeaveDeviceManager");
    }

    public void onDeviceEnumerationResponse(String descriptor, String deviceId) {
        String endpoint = "/v1/devices/{id}/traits";
        String auth = "Authorization";
        String bearer = "Bearer ";
    }
}
"#,
    )
    .expect("write WeaveDeviceManager");
    fs::write(
        grpc_dir.join("TaclFutureCallback.java"),
        r#"
package com.example.media.transport.common;

import io.grpc.Status;
import org.webrtc.SessionDescription;

public class TaclFutureCallback {
    public void onResult(Status status, SessionDescription description) {}
}
"#,
    )
    .expect("write TaclFutureCallback");
}

fn write_jadx_security_constants_tree(root: &Path) {
    let constants_dir = root.join("sources/com/example/security");
    let third_party_dir = root.join("sources/androidx/core/app");
    let google_common_dir = root.join("sources/com/google/common/net");
    fs::create_dir_all(&constants_dir).expect("security constants dir");
    fs::create_dir_all(&third_party_dir).expect("third party dir");
    fs::create_dir_all(&google_common_dir).expect("google common dir");

    fs::write(
        constants_dir.join("BaseConstant.java"),
        r#"
package com.example.security;

public final class BaseConstant {
    public static final String APP_SIGN_SECRET = "fixture";
    public static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AEXAMPLEPUBLICKEY";
    public static final String DEFAULT_AP_PWD = "12345678";
    public static final String DOG_ADDRESS = "192.168.12.1";
    public static final String UDP_IP = "231.1.1.1";
    public static final int UDP_PORT = 10131;
}
"#,
    )
    .expect("write BaseConstant");

    fs::write(
        constants_dir.join("AESUtil.java"),
        r#"
package com.example.security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AESUtil {
    private static final String CIPHER_ALGORITHM = "AES/CFB128/NoPadding";
    private static final byte[] IV = byteArrayOfInts(40, 65, 174, 151);
    private static final byte[] secretKey = byteArrayOfInts(223, 152, 183, 21);

    private static byte[] byteArrayOfInts(int... ints) {
        return new byte[] {(byte) ints.length};
    }

    public void encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(1, new SecretKeySpec(secretKey, "AES"), new IvParameterSpec(IV));
    }
}
"#,
    )
    .expect("write AESUtil");

    fs::write(
        constants_dir.join("AESGCMUtil.java"),
        r#"
package com.example.security;

import javax.crypto.Cipher;

public final class AESGCMUtil {
    private static final byte[] keyBytes = byteArrayOfInts(232, 86, 179, 1);

    private static byte[] byteArrayOfInts(int... ints) {
        return new byte[] {(byte) ints.length};
    }

    public void encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    }
}
"#,
    )
    .expect("write AESGCMUtil");

    fs::write(
        constants_dir.join("AESZeroKey.java"),
        r#"
package com.example.security;

import javax.crypto.spec.SecretKeySpec;

public final class AESZeroKey {
    public void useFallback() {
        SecretKeySpec spec = new SecretKeySpec(new byte[16], "AES");
    }
}
"#,
    )
    .expect("write AESZeroKey");

    fs::write(
        third_party_dir.join("NotificationCompat.java"),
        r#"
package androidx.core.app;

public final class NotificationCompat {
    public static final String VISIBILITY_SECRET = "library-secret";
    public static final int IMPORTANCE_DEFAULT = 3;
}
"#,
    )
    .expect("write NotificationCompat");

    fs::write(
        google_common_dir.join("HttpHeaders.java"),
        r#"
package com.google.common.net;

public final class HttpHeaders {
    public static final String PUBLIC_KEY_PINS = "Public-Key-Pins";
}
"#,
    )
    .expect("write HttpHeaders");
}

fn write_jadx_noisy_tree(root: &Path) {
    let noisy_dir = root.join("sources/com/example/noisy");
    fs::create_dir_all(&noisy_dir).expect("noisy dir");
    fs::write(
        noisy_dir.join("NoisyManager.java"),
        r#"
package com.example.noisy;

import android.util.Log;
import java.util.Random;
import io.grpc.Status;

public class NoisyManager {
    public void getStatus() {}
    public void helperMethod() {}
    public void computeHash() {}
    public void onDeviceEnumerationResponse(String id) {}
}

class UtilityHelper {
    public void startJob() {}
    public void readState() {}
}
"#,
    )
    .expect("write NoisyManager");
}

fn write_jadx_tls_storage_tree(root: &Path) {
    let net_dir = root.join("sources/com/example/net");
    let store_dir = root.join("sources/com/example/store");
    fs::create_dir_all(&net_dir).expect("net dir");
    fs::create_dir_all(&store_dir).expect("store dir");

    fs::write(
        net_dir.join("RetrofitFactory.java"),
        r#"
package com.example.net;

import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

public final class RetrofitFactory {
    private static final HostnameVerifier UNSAFE_VERIFIER = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    private static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };
}
"#,
    )
    .expect("write RetrofitFactory");

    fs::write(
        store_dir.join("TokenStore.java"),
        r#"
package com.example.store;

import com.tencent.mmkv.MMKV;

public final class TokenStore {
    public static final String KEY_SP_TOKEN = "token";
    public static final String KEY_SP_REFRESH_TOKEN = "refresh_token";

    public void persist(String token, String refreshToken) {
        MMKV.defaultMMKV().encode(KEY_SP_TOKEN, token);
        MMKV.defaultMMKV().encode(KEY_SP_REFRESH_TOKEN, refreshToken);
    }
}
"#,
    )
    .expect("write TokenStore");
}

fn write_jadx_endpoint_rank_tree(root: &Path) {
    let dir = root.join("sources/com/example/ranked");
    fs::create_dir_all(&dir).expect("ranked dir");
    fs::write(
        dir.join("RankedRoutes.java"),
        r#"
package com.example.ranked;

public class RankedRoutes {
    public void dispatch(String route) {
        String a = "/api/v1/devices/{sn}/live/openStream/start";
        String b = "/api/v1/users/devices/{sn}/bind/check";
        String c = "/api/v1/devices/{sn}/commands/hatch/control";
        String d = "/api/v1/hms/{hms}/faq";
        String e = "/api/v1/devices/{sn}/maps/mapContentUpdate";
        String f = "/api/v1/devices/{sn}/moduleFile/status";
        String g = "https://static.example/assets/pairing-code.webp";
        String h = "deviceapp://devices/controller";
    }
}
"#,
    )
    .expect("write RankedRoutes");
}

fn write_jadx_weave_deep_tree(root: &Path) {
    let weave_dir = root.join("sources/nl/Weave/DeviceManager");
    let security_dir = root.join("sources/com/nestlabs/weave/security");
    let matter_dir = root.join("sources/com/google/android/gms/home/matter/commissioning");
    let ble_dir = root.join("sources/com/example/ble");
    fs::create_dir_all(&weave_dir).expect("weave deep dir");
    fs::create_dir_all(&security_dir).expect("security dir");
    fs::create_dir_all(&matter_dir).expect("matter dir");
    fs::create_dir_all(&ble_dir).expect("ble dir");
    fs::write(
        weave_dir.join("WeaveDeviceManager.java"),
        r#"
package nl.Weave.DeviceManager;

public class WeaveDeviceManager {
    public void beginRendezvousDeviceAccessToken(byte[] token, IdentifyDeviceCriteria criteria) {}
    public void beginRendezvousDevicePairingCode(String code, IdentifyDeviceCriteria criteria) {}
    public void beginCreateFabric() {}
    public void beginIdentifyDevice() {}
    public void onDeviceEnumerationResponse(WeaveDeviceDescriptor descriptor, String addr) {}
}
"#,
    )
    .expect("write WeaveDeviceManager deep");
    fs::write(
        security_dir.join("WeaveSecuritySupport.java"),
        r#"
package com.nestlabs.weave.security;

public final class WeaveSecuritySupport {
    public static native byte[] x509CertificateToWeave(byte[] cert);
    public static native byte[] weaveCertificateToX509(byte[] cert);
    public static native byte[] generateKeyExportRequest(int type, long id, byte[] key);
    public static native boolean isValidPairingCode(String code);
}
"#,
    )
    .expect("write WeaveSecuritySupport");
    fs::write(
        matter_dir.join("SharedDeviceData.java"),
        r#"
package com.example.matter.commissioning;

public class SharedDeviceData {
    public String manualPairingCode;
    public long commissioningWindowExpirationMillis;
}
"#,
    )
    .expect("write SharedDeviceData");
    fs::write(
        ble_dir.join("BleScanner.java"),
        r#"
package com.example.ble;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothGatt;

public class BleScanner {
    public BluetoothGatt connect(BluetoothAdapter adapter) {
        return null;
    }
}
"#,
    )
    .expect("write BleScanner");
}

fn write_fake_jadx(bin_dir: &Path) {
    let script_path = bin_dir.join("jadx");
    fs::write(
        &script_path,
        r#"#!/bin/sh
set -eu
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-d" ]; then
    out="$2"
    shift 2
    continue
  fi
  shift
done
mkdir -p "$out/sources/com/example"
cat > "$out/sources/com/example/DeepLinkActivity.java" <<'EOF'
package com.example;
import android.content.Intent;
import android.net.Uri;
public class DeepLinkActivity {
    public void onCreate(Intent intent) {
        Uri uri = intent.getData();
        new Router().dispatch(uri.toString());
    }
}
EOF
cat > "$out/sources/com/example/Router.java" <<'EOF'
package com.example;
public class Router {
    public void dispatch(String route) {
        String endpoint = "/api/v1/devices/{sn}";
        String auth = "Authorization";
        String mqtt = "mqtt://broker/devices/{sn}";
    }
}
EOF
"#,
    )
    .expect("write fake jadx");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).expect("chmod");
    }
}

fn write_fake_jadx_nonzero(bin_dir: &Path) {
    let script_path = bin_dir.join("jadx");
    fs::write(
        &script_path,
        r#"#!/bin/sh
set -eu
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-d" ]; then
    out="$2"
    shift 2
    continue
  fi
  shift
done
mkdir -p "$out/sources/com/example"
cat > "$out/sources/com/example/DeepLinkActivity.java" <<'EOF'
package com.example;
public class DeepLinkActivity {
    public void onCreate() {
        new Router().dispatch("route://deeplink");
    }
}
EOF
cat > "$out/sources/com/example/Router.java" <<'EOF'
package com.example;
public class Router {
    public void dispatch(String route) {
        String endpoint = "/api/v1/devices/{sn}";
    }
}
EOF
exit 1
"#,
    )
    .expect("write fake nonzero jadx");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).expect("chmod");
    }
}

fn write_fake_apkanalyzer(bin_dir: &Path, package_name: &str) {
    let script_path = bin_dir.join("apkanalyzer");
    let manifest = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<manifest package="{package_name}">
  <uses-permission android:name="android.permission.INTERNET" />
  <application android:debuggable="true" android:usesCleartextTraffic="true">
    <activity android:name=".DeepLinkActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:scheme="https" android:host="binary.example" android:pathPrefix="/devices/" />
      </intent-filter>
    </activity>
  </application>
</manifest>
"#
    );
    fs::write(
        &script_path,
        format!(
            "#!/bin/sh\nset -eu\nif [ \"$1\" = \"manifest\" ] && [ \"$2\" = \"print\" ]; then\ncat <<'EOF'\n{manifest}EOF\n  exit 0\nfi\nexit 1\n"
        ),
    )
    .expect("write fake apkanalyzer");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).expect("chmod");
    }
}

fn write_jadx_flutter_sparse_tree(root: &Path) {
    fs::create_dir_all(root.join("sources/com/example/deviceapp")).expect("jadx dirs");
    fs::write(
        root.join("sources/com/example/deviceapp/MainActivity.java"),
        r#"
package com.example.deviceapp;

public final class MainActivity extends io.flutter.embedding.android.FlutterActivity {
}
"#,
    )
    .expect("write MainActivity");
}

fn write_jadx_flutter_sparse_tree_with_noise(root: &Path) {
    write_jadx_flutter_sparse_tree(root);

    let binder_dir = root.join("sources/com/google/android/gms/common/internal");
    let webview_dir = root.join("sources/io/flutter/plugins/webviewflutter");
    fs::create_dir_all(&binder_dir).expect("binder dirs");
    fs::create_dir_all(&webview_dir).expect("webview dirs");

    fs::write(
        binder_dir.join("Stub.java"),
        r#"
package com.google.android.gms.common.internal;

public class Stub {
    static {
        System.loadLibrary("gmscore");
    }

    public void onTransact(byte[] blob, int length) {
        String binder = "binder";
        String parcel = "parcel";
        String copy = "copy";
        String size = "size";
    }
}
"#,
    )
    .expect("write noisy binder");

    fs::write(
        webview_dir.join("GeneratedProxyApi.java"),
        r#"
package io.flutter.plugins.webviewflutter;

public final class GeneratedProxyApi {
    public void wire(Object webView, Object bridge) {
        webView.addJavascriptInterface(bridge, "bridge");
        webView.loadUrl("https://device.example/bridge");
        String tag = "webview";
    }
}
"#,
    )
    .expect("write noisy webview");
}

fn write_flutter_runtime_base_apk(path: &std::path::Path, package_name: &str) {
    let file = std::fs::File::create(path).expect("create apk");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    let manifest = format!(
        r#"
    <manifest package="{package_name}">
      <application>
        <activity android:name=".MainActivity" android:exported="true" />
      </application>
    </manifest>
    "#
    );

    zip.start_file("AndroidManifest.xml", opts)
        .expect("manifest entry");
    use std::io::Write as _;
    zip.write_all(manifest.as_bytes()).expect("manifest bytes");
    zip.start_file("classes.dex", opts).expect("classes.dex");
    zip.write_all(b"dex").expect("dex bytes");
    zip.start_file("assets/flutter_assets/.env", opts)
        .expect("env entry");
    zip.write_all(b"GOOGLE_ANDROID_CLIENT_ID=\"178409912024-test.apps.googleusercontent.com\"\n")
        .expect("env bytes");
    zip.start_file("assets/flutter_assets/AssetManifest.json", opts)
        .expect("asset manifest");
    zip.write_all(
        br#"{".env":[".env"],"assets/device-firmware-1.0.zip":["assets/device-firmware-1.0.zip"],"assets/lua_scripts/main.lua":["assets/lua_scripts/main.lua"]}"#,
    )
    .expect("asset manifest bytes");
    zip.start_file("assets/flutter_assets/assets/lua_scripts/main.lua", opts)
        .expect("lua entry");
    zip.write_all(
        br#"device.bluetooth.receive_callback(function(message)
device.bluetooth.send(message)
print(device.FIRMWARE_VERSION)
end)
"#,
    )
    .expect("lua bytes");
    zip.start_file("assets/flutter_assets/assets/device-firmware-1.0.zip", opts)
        .expect("firmware entry");
    zip.write_all(b"PK\x03\x04firmware")
        .expect("firmware bytes");
    zip.finish().expect("finish zip");
}

fn write_flutter_runtime_split_apk(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create split");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("AndroidManifest.xml", opts)
        .expect("manifest entry");
    use std::io::Write as _;
    zip.write_all(b"<manifest package=\"com.example.deviceapp\" />")
        .expect("manifest bytes");
    zip.start_file("lib/armeabi-v7a/libapp.so", opts)
        .expect("libapp");
    zip.write_all(
        b"package:deviceapp/bluetooth.dart\0package:deviceapp/pages/login.dart\0package:deviceapp/pages/pairing.dart\0package:deviceapp/models/app_logic_model.dart\0package:webview_flutter_android/src/android_webview.dart\0package:flutter_blue_plus/src/flutter_blue_plus.dart\0plugins.flutter.io/webview\0dev.flutter.pigeon.webview_flutter_android.WebViewHostApi.loadUrl\0https://api.device.example/v1/login\0https://api.device.example/v1/user\0Starting firmware update\0",
    )
    .expect("libapp bytes");
    zip.start_file("lib/armeabi-v7a/libflutter.so", opts)
        .expect("libflutter");
    zip.write_all(b"flutter").expect("libflutter bytes");
    zip.finish().expect("finish zip");
}

fn write_flutter_runtime_verbose_webview_split_apk(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create split");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("AndroidManifest.xml", opts)
        .expect("manifest entry");
    use std::io::Write as _;
    zip.write_all(b"<manifest package=\"com.example.deviceapp\" />")
        .expect("manifest bytes");
    zip.start_file("lib/armeabi-v7a/libapp.so", opts)
        .expect("libapp");
    zip.write_all(
        b"package:deviceapp/bluetooth.dart\0package:deviceapp/pages/login.dart\0package:deviceapp/pages/pairing.dart\0package:deviceapp/models/app_logic_model.dart\0package:webview_flutter_android/src/android_webview.dart\0package:flutter_blue_plus/src/flutter_blue_plus.dart\0plugins.flutter.io/webview\0dev.flutter.pigeon.webview_flutter_android.WebViewHostApi.loadUrl\0dev.flutter.pigeon.webview_flutter_android.CustomViewCallbackFlutterApi.create\0dev.flutter.pigeon.webview_flutter_android.WebChromeClientFlutterApi.onConsoleMessage\0dev.flutter.pigeon.webview_flutter_android.JavaScriptChannelFlutterApi.postMessage\0https://api.device.example/v1/login\0https://api.device.example/v1/user\0Starting firmware update\0",
    )
    .expect("libapp bytes");
    zip.start_file("lib/armeabi-v7a/libflutter.so", opts)
        .expect("libflutter");
    zip.write_all(b"flutter").expect("libflutter bytes");
    zip.finish().expect("finish zip");
}

fn write_flutter_runtime_chain_stress_split_apk(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create split");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("AndroidManifest.xml", opts)
        .expect("manifest entry");
    use std::io::Write as _;
    zip.write_all(b"<manifest package=\"com.example.deviceapp\" />")
        .expect("manifest bytes");
    zip.start_file("lib/armeabi-v7a/libapp.so", opts)
        .expect("libapp");
    zip.write_all(
        b"package:deviceapp/bluetooth.dart\0package:deviceapp/pages/login.dart\0package:deviceapp/pages/pairing.dart\0package:deviceapp/models/app_logic_model.dart\0package:webview_flutter_android/src/android_webview.dart\0package:flutter_blue_plus/src/flutter_blue_plus.dart\0plugins.flutter.io/webview\0dev.flutter.pigeon.webview_flutter_android.WebViewHostApi.loadUrl\0generic_sign_in_android\0https://api.device.example/v1/login\0https://api.device.example/v1/user\0https://api.device.example/v1/user/signout\0https://api.device.example/v1/firmware/update\0https://device.example/privacy-policy\0https://device.example/terms\0Starting firmware update\0",
    )
    .expect("libapp bytes");
    zip.start_file("lib/armeabi-v7a/libflutter.so", opts)
        .expect("libflutter");
    zip.write_all(b"flutter").expect("libflutter bytes");
    zip.finish().expect("finish zip");
}

fn write_embedded_apk_bundle_container(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create outer bundle");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("manifest.json", opts)
        .expect("manifest.json");
    use std::io::Write as _;
    zip.write_all(br#"{"name":"APKPure bundle"}"#)
        .expect("manifest json bytes");
    zip.start_file("com.example.deviceapp.apk", opts)
        .expect("embedded base");
    zip.write_all(b"embedded-apk").expect("embedded apk bytes");
    zip.start_file("config.armeabi_v7a.apk", opts)
        .expect("embedded split");
    zip.write_all(b"embedded-split")
        .expect("embedded split bytes");
    zip.finish().expect("finish zip");
}

fn run_help(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(args)
        .output()
        .expect("help command runs");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn android_help_exposes_expected_subcommands() {
    let stdout = run_help(&["android", "--help"]);
    assert!(stdout.contains("inventory"));
    assert!(stdout.contains("discover"));
    assert!(stdout.contains("chains"));
    assert!(stdout.contains("locality"));
    assert!(stdout.contains("benchmark"));
}

#[test]
fn android_inventory_help_exposes_apk_and_splits_flags() {
    let stdout = run_help(&["android", "inventory", "--help"]);
    assert!(stdout.contains("--apk"));
    assert!(stdout.contains("--splits"));
    assert!(stdout.contains("--json"));
}

#[test]
fn android_locality_help_exposes_apk_and_splits_flags() {
    let stdout = run_help(&["android", "locality", "--help"]);
    assert!(stdout.contains("--apk"));
    assert!(stdout.contains("--splits"));
    assert!(stdout.contains("--json"));
}

#[test]
fn android_discover_help_exposes_semantic_bundle_and_splits_flags() {
    let stdout = run_help(&["android", "discover", "--help"]);
    assert!(stdout.contains("--apk"));
    assert!(stdout.contains("--splits"));
    assert!(stdout.contains("--semantic-bundle"));
    assert!(stdout.contains("--jadx-root"));
    assert!(stdout.contains("--semantic-bundle-out"));
    assert!(stdout.contains("--semantic-mode"));
    assert!(stdout.contains("--family"));
    assert!(stdout.contains("--runtime-manifest-out"));
    assert!(stdout.contains("--progress"));
    assert!(stdout.contains("--json"));
}

#[test]
fn android_chains_help_exposes_truthful_chain_guidance() {
    let stdout = run_help(&["android", "chains", "--help"]);
    assert!(stdout.contains("--apk"));
    assert!(stdout.contains("--semantic-bundle"));
    assert!(stdout.contains("--entry"));
    assert!(stdout.contains("--sink"));
    assert!(stdout.contains("runtime role clusters"));
    assert!(stdout.contains("informational endpoints"));
    assert!(stdout.contains("bluetooth --sink main.lua"));
    assert!(stdout.contains("login --sink signout"));
}

#[test]
fn android_discover_defaults_to_human_progress_on_stderr() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    write_test_apk(&base_apk, false);
    write_jadx_router_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let _report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("Android Discover Progress"), "{stderr}");
    assert!(stderr.contains("Inventory APKs"), "{stderr}");
    assert!(stderr.contains("Index JADX sources"), "{stderr}");
    assert!(stderr.contains("Rank discovery leads"), "{stderr}");
}

#[test]
fn android_discover_json_consumes_semantic_bundle_and_stays_honest() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("feature.apk");
    let semantic_bundle = dir.path().join("bundle.json");
    write_test_apk(&base_apk, false);
    write_test_apk(&split_apk, true);
    write_semantic_bundle(&semantic_bundle, "com.example.app");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--semantic-bundle",
            semantic_bundle.to_str().expect("bundle path"),
            "--family",
            "remote-router-gadget",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        report.get("status").and_then(Value::as_str),
        Some("partial-family-ready")
    );
    assert_eq!(
        report.get("family_filter").and_then(Value::as_str),
        Some("remote-router-gadget")
    );
    assert_eq!(report.get("lead_count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        report
            .get("leads")
            .and_then(Value::as_array)
            .and_then(|leads| leads.first())
            .and_then(|lead| lead.get("family"))
            .and_then(Value::as_str),
        Some("remote-router-gadget")
    );
    assert_eq!(
        report
            .get("semantic")
            .and_then(|value| value.get("bundle_version"))
            .and_then(Value::as_str),
        Some("android-semantic/v1alpha1")
    );
    assert_eq!(
        report
            .get("semantic")
            .and_then(|value| value.get("observed_fact_count"))
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        report
            .get("semantic")
            .and_then(|value| value.get("inferred_fact_count"))
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        report
            .get("inventory_summary")
            .and_then(|value| value.get("container_count"))
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        report
            .get("semantic")
            .and_then(|value| value.get("revelation_count"))
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        report
            .get("semantic")
            .and_then(|value| value.get("observed_revelation_count"))
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        report
            .get("semantic")
            .and_then(|value| value.get("inferred_revelation_count"))
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        report
            .get("semantic")
            .and_then(|value| value.get("target_package_name"))
            .and_then(Value::as_str),
        Some("com.example.app")
    );
    let first_lead = report
        .get("leads")
        .and_then(Value::as_array)
        .and_then(|leads| leads.first())
        .expect("first lead");
    assert!(
        first_lead
            .get("why_matched")
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(|item| {
                item.as_str()
                    .is_some_and(|value| value.contains("supporting revelation"))
            })),
        "{first_lead:?}"
    );
    assert_eq!(
        report
            .get("warnings")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    assert!(
        report["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| {
                warning
                    .as_str()
                    .is_some_and(|text| text.contains("requested top_k"))
            })),
        "report={report:?}"
    );
    assert_eq!(
        report.get("message").and_then(Value::as_str),
        Some("Android family interpretation is available for the supported families.")
    );
}

#[test]
fn android_discover_keeps_zero_lead_honesty_when_revelations_do_not_back_requested_family() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let semantic_bundle = dir.path().join("bundle.json");
    write_test_apk(&base_apk, false);
    write_semantic_bundle(&semantic_bundle, "com.example.app");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--semantic-bundle",
            semantic_bundle.to_str().expect("bundle path"),
            "--family",
            "webview-bridge-uri",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report.get("lead_count").and_then(Value::as_u64), Some(0));
    assert!(
        report
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("No leads:")),
        "{report:?}"
    );
}

#[test]
fn android_discover_json_warns_when_bundle_target_mismatches_manifest() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let semantic_bundle = dir.path().join("bundle.json");
    write_test_apk(&base_apk, false);
    write_semantic_bundle(&semantic_bundle, "com.other.app");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--semantic-bundle",
            semantic_bundle.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        report
            .get("warnings")
            .and_then(Value::as_array)
            .and_then(|warnings| warnings.first())
            .and_then(Value::as_str),
        Some("semantic bundle target package com.other.app does not match manifest package com.example.app")
    );
}

#[test]
fn android_explain_human_readable_output_includes_revelations_support_and_rationale() {
    let dir = tempdir().expect("tempdir");
    let semantic_bundle = dir.path().join("semantic-bundle.json");
    write_semantic_bundle(&semantic_bundle, "com.example.app");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "explain",
            "--semantic-bundle",
            semantic_bundle.to_str().expect("bundle path"),
        ])
        .output()
        .expect("android explain runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.contains("router dispatch surface"), "{stdout}");
    assert!(stdout.contains("deep-link trust boundary"), "{stdout}");
    assert!(stdout.contains("support: Observed"), "{stdout}");
    assert!(stdout.contains("support: Inferred"), "{stdout}");
    assert!(stdout.contains("switch over route token"), "{stdout}");
    assert!(
        stdout.contains("manifest filter aligns with router sink"),
        "{stdout}"
    );
    assert!(stdout.contains("subsystems: subsystem-router"), "{stdout}");
    assert!(stdout.contains("context:"), "{stdout}");
    assert!(
        stdout.contains("evidence=sym-router-dispatch; control-router-dispatch"),
        "{stdout}"
    );
    assert!(
        stdout.contains("members=sym-router-dispatch, control-router-dispatch"),
        "{stdout}"
    );
    assert!(
        stdout.contains("javascript_interface_methods: 1"),
        "{stdout}"
    );
    assert!(stdout.contains("webSendCmdRes(String)"), "{stdout}");
    assert!(stdout.contains("command-dispatch"), "{stdout}");
}

#[test]
fn android_inventory_json_reports_apk_facts_and_split_counts() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("feature.apk");
    write_test_apk(&base_apk, false);
    write_test_apk(&split_apk, true);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "inventory",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--json",
        ])
        .output()
        .expect("android inventory runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        report
            .get("summary")
            .and_then(|value| value.get("container_count"))
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        report
            .get("summary")
            .and_then(|value| value.get("dex_file_count"))
            .and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        report
            .get("summary")
            .and_then(|value| value.get("native_lib_count"))
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        report
            .get("summary")
            .and_then(|value| value.get("component_count"))
            .and_then(Value::as_u64),
        Some(3)
    );
}

#[test]
fn android_inventory_accepts_multiple_split_values_after_single_flag() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_one = dir.path().join("feature-one.apk");
    let split_two = dir.path().join("feature-two.apk");
    write_test_apk(&base_apk, false);
    write_test_apk(&split_one, true);
    write_test_apk(&split_two, true);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "inventory",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_one.to_str().expect("split one"),
            split_two.to_str().expect("split two"),
            "--json",
        ])
        .output()
        .expect("android inventory runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        report
            .get("summary")
            .and_then(|value| value.get("container_count"))
            .and_then(Value::as_u64),
        Some(3)
    );
}

#[test]
fn android_locality_json_classifies_base_and_split_artifacts() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("feature.apk");
    write_test_apk(&base_apk, false);
    write_test_apk(&split_apk, true);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "locality",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--json",
        ])
        .output()
        .expect("android locality runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        report
            .get("summary")
            .and_then(|value| value.get("app_local"))
            .and_then(Value::as_u64),
        Some(6)
    );
    assert_eq!(
        report
            .get("summary")
            .and_then(|value| value.get("split_feature_local"))
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        report
            .get("summary")
            .and_then(|value| value.get("bundled_native_lib"))
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        report
            .get("summary")
            .and_then(|value| value.get("unknown"))
            .and_then(Value::as_u64),
        Some(1)
    );
}

#[test]
fn android_benchmark_json_reports_summary_for_fixture_manifest() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/benchmarks/android_discovery_manifest.json");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "benchmark",
            "--manifest",
            manifest.to_str().expect("manifest path"),
            "--json",
        ])
        .output()
        .expect("android benchmark runs");

    assert!(output.status.success(), "{output:?}");
    let summary: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        summary.get("suite").and_then(Value::as_str),
        Some("android-discovery-v1")
    );
    assert_eq!(summary.get("top_k").and_then(Value::as_u64), Some(3));
    assert_eq!(summary.get("pass_count").and_then(Value::as_u64), Some(6));
}

#[test]
fn android_discover_json_derives_semantic_bundle_from_jadx_root() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    write_test_apk(&base_apk, false);
    write_jadx_router_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--family",
            "remote-router-gadget",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        report
            .get("semantic")
            .and_then(|value| value.get("bundle_version"))
            .and_then(Value::as_str),
        Some("android-semantic/v1alpha1")
    );
    assert!(
        report
            .get("lead_count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count >= 1),
        "{report}"
    );
    assert_eq!(
        report
            .get("leads")
            .and_then(Value::as_array)
            .and_then(|leads| leads.first())
            .and_then(|lead| lead.get("family"))
            .and_then(Value::as_str),
        Some("remote-router-gadget")
    );
}

#[test]
fn android_discover_derived_bundle_extracts_caller_validation_guards() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("surface.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("guarded-router.semantic.json");
    write_surface_manifest_apk(&base_apk);
    write_jadx_guarded_router_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--family",
            "remote-router-gadget",
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    assert!(bundle["trust_boundaries"]
        .as_array()
        .expect("boundaries")
        .iter()
        .any(|boundary| {
            boundary["kind"] == "deep-link-to-internal-router"
                && boundary["guard"]
                    .as_str()
                    .is_some_and(|guard| guard.contains("getCallingPackage"))
        }));
}

#[test]
fn android_discover_does_not_leak_unrelated_caller_guards_into_router_boundary() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("surface.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("unguarded-router.semantic.json");
    write_surface_manifest_apk(&base_apk);
    write_jadx_guarded_router_false_positive_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--family",
            "remote-router-gadget",
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    assert!(bundle["trust_boundaries"]
        .as_array()
        .expect("boundaries")
        .iter()
        .any(|boundary| {
            boundary["kind"] == "deep-link-to-internal-router"
                && boundary["guard"].is_null()
                && boundary["notes"].as_array().is_some_and(|notes| {
                    notes
                        .iter()
                        .any(|note| note == "no caller validation detected")
                })
        }));
}

#[test]
fn android_discover_json_emits_concrete_router_triggers_and_provenance_summary() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("surface.apk");
    let jadx_root = dir.path().join("jadx");
    write_surface_manifest_apk(&base_apk);
    write_jadx_router_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--family",
            "remote-router-gadget",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let lead = report["leads"]
        .as_array()
        .and_then(|leads| leads.first())
        .expect("first lead");
    assert_eq!(lead["suggested_trigger_recipe"][0]["kind"], "adb-deeplink");
    assert!(lead["suggested_trigger_recipe"][0]["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("adb shell am start")));
    assert!(lead["suggested_trigger_recipe"][0]["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("https://example.app/devices/FUZZ")));
    assert!(lead["provenance_summary"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
}

#[test]
fn android_discover_json_marks_synthetic_binder_placeholders_and_unresolved_symbols() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("binder.semantic.json");
    write_test_apk(&base_apk, false);
    write_jadx_binder_placeholder_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--family",
            "binder-native-boundary",
            "--semantic-mode",
            "dense",
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let lead = report["leads"]
        .as_array()
        .and_then(|leads| leads.first())
        .expect("first lead");
    assert_eq!(lead["symbol"], "com.example.NativeBridge.parseBlob");
    assert_eq!(lead["symbol_resolved"], false);

    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    assert!(bundle["symbol_identities"]
        .as_array()
        .expect("symbols")
        .iter()
        .any(|symbol| {
            symbol["qualified_name"] == "com.example.NativeBridge.parseBlob"
                && symbol["synthetic"] == true
        }));
    assert!(bundle["native_semantics"]
        .as_array()
        .expect("native semantics")
        .iter()
        .any(|native| {
            native["symbol_name"] == "Java_com_example_NativeBridge_parseBlob"
                && native["synthetic"] == true
        }));
}

#[test]
fn android_discover_json_uses_resolved_binder_symbol_for_jni_companion() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("binder-resolved.semantic.json");
    write_test_apk(&base_apk, false);
    write_jadx_binder_resolved_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--family",
            "binder-native-boundary",
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    assert!(bundle["native_semantics"]
        .as_array()
        .expect("native semantics")
        .iter()
        .any(|native| {
            native["symbol_name"] == "Java_com_example_binder_BlobBridge_onTransact"
                && native["synthetic"] == false
        }));
}

#[test]
fn android_discover_default_mode_suppresses_third_party_only_router_and_binder_noise() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("unitree.apk");
    let jadx_root = dir.path().join("jadx");
    write_manifest_apk_with_package(&base_apk, "com.unitree.doggo2");
    write_jadx_third_party_noise_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--progress",
            "quiet",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(report["leads"]
        .as_array()
        .expect("leads")
        .iter()
        .all(|lead| lead["family"] != "remote-router-gadget"));
    assert!(report["leads"]
        .as_array()
        .expect("leads")
        .iter()
        .all(|lead| lead["family"] != "binder-native-boundary"));
    assert!(report["leads"]
        .as_array()
        .expect("leads")
        .iter()
        .all(|lead| lead["family"] != "capability-chain-confused-deputy"));
}

#[test]
fn android_discover_default_mode_prefers_app_owned_webview_surface_over_library_scaffolding() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("unitree.apk");
    let jadx_root = dir.path().join("jadx");
    write_manifest_apk_with_package(&base_apk, "com.unitree.doggo2");
    write_jadx_unitree_owned_webview_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--family",
            "webview-bridge-uri",
            "--progress",
            "quiet",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["lead_count"], 1);
    assert_eq!(
        report["leads"][0]["symbol"],
        "com.unitree.doggo2.ui.activity.web.WebActivity.loadUrl"
    );
    assert_eq!(report["leads"][0]["symbol_resolved"], true);
}

#[test]
fn android_discover_json_auto_runs_jadx_and_can_persist_derived_bundle() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let bin_dir = dir.path().join("bin");
    let bundle_out = dir.path().join("derived-bundle.json");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    write_test_apk(&base_apk, false);
    write_fake_jadx(&bin_dir);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--family",
            "remote-router-gadget",
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle out"),
            "--json",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    assert!(
        bundle_out.exists(),
        "derived semantic bundle was not written"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(
        report
            .get("lead_count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count >= 1),
        "{report}"
    );
    assert_eq!(
        report
            .get("leads")
            .and_then(Value::as_array)
            .and_then(|leads| leads.first())
            .and_then(|lead| lead.get("family"))
            .and_then(Value::as_str),
        Some("remote-router-gadget")
    );
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    assert_eq!(
        bundle
            .get("extractor")
            .and_then(|value| value.get("extractor_id"))
            .and_then(Value::as_str),
        Some("fat-android-heuristic-jadx")
    );
}

#[test]
fn android_discover_auto_runs_nonzero_jadx_when_tree_is_usable() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let bin_dir = dir.path().join("bin");
    let bundle_out = dir.path().join("derived-bundle.json");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    write_test_apk(&base_apk, false);
    write_fake_jadx_nonzero(&bin_dir);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle out"),
            "--json",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    assert_eq!(bundle["extractor"]["degraded"], true, "bundle={bundle:?}");
    assert!(
        bundle["extractor"]["notes"]
            .as_array()
            .is_some_and(|notes| notes.iter().any(|note| {
                note.as_str()
                    .is_some_and(|text| text.contains("jadx exited non-zero"))
            })),
        "bundle={bundle:?}"
    );
}

#[test]
fn android_discover_extracts_flutter_runtime_semantics_from_assets_and_splits() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("config.armeabi_v7a.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("flutter-runtime.semantic.json");
    write_flutter_runtime_base_apk(&base_apk, "com.example.deviceapp");
    write_flutter_runtime_split_apk(&split_apk);
    write_jadx_flutter_sparse_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");
    let controls = bundle["control_surfaces"]
        .as_array()
        .expect("controls array");
    let revelations = bundle["revelations"].as_array().expect("revelations array");

    for (kind, subject) in [
        ("runtime.app-framework", "flutter"),
        ("source.dart-package", "package:deviceapp/bluetooth.dart"),
        ("source.dart-package", "package:deviceapp/pages/login.dart"),
        ("runtime.plugin", "flutter_blue_plus"),
        ("runtime.plugin", "webview_flutter_android"),
        ("artifact.bundled-script", "assets/lua_scripts/main.lua"),
        (
            "artifact.bundled-firmware",
            "assets/device-firmware-1.0.zip",
        ),
        ("runtime.env-key", "GOOGLE_ANDROID_CLIENT_ID"),
    ] {
        assert!(
            facts
                .iter()
                .any(|fact| fact["kind"] == kind && fact["subject"] == subject),
            "missing fact {kind}={subject}; got {facts:?}"
        );
    }

    for (kind, subject, role) in [
        (
            "role.runtime-package",
            "package:deviceapp/bluetooth.dart",
            "local-device-control",
        ),
        (
            "role.runtime-package",
            "package:deviceapp/pages/login.dart",
            "account-auth",
        ),
        (
            "role.runtime-plugin",
            "flutter_blue_plus",
            "local-device-control",
        ),
        (
            "role.runtime-plugin",
            "webview_flutter_android",
            "embedded-web-content",
        ),
        (
            "role.runtime-endpoint",
            "https://api.device.example/v1/login",
            "account-auth",
        ),
        (
            "role.runtime-asset",
            "assets/lua_scripts/main.lua",
            "local-device-control",
        ),
    ] {
        assert!(
            facts.iter().any(|fact| {
                fact["kind"] == kind
                    && fact["subject"] == subject
                    && fact["attributes"]["role"] == role
            }),
            "missing runtime role fact {kind}={subject} role={role}; got {facts:?}"
        );
    }

    let correlations = bundle["correlations"]
        .as_array()
        .expect("correlations array");
    assert!(
        correlations.iter().any(|correlation| {
            correlation["kind"] == "runtime-role-cluster"
                && correlation["rationale"]
                    .as_str()
                    .is_some_and(|text| text.contains("local-device-control"))
        }),
        "correlations={correlations:?}"
    );
    assert!(
        correlations.iter().any(|correlation| {
            correlation["kind"] == "runtime-role-cluster"
                && correlation["rationale"]
                    .as_str()
                    .is_some_and(|text| text.contains("account-auth"))
        }),
        "correlations={correlations:?}"
    );

    assert!(
        controls.iter().any(|surface| {
            surface["kind"] == "local-device-control-surface"
                && surface["trigger"] == "assets/lua_scripts/main.lua"
        }),
        "controls={controls:?}"
    );
    assert!(
        controls.iter().any(|surface| {
            surface["kind"] == "http-api-endpoint"
                && surface["trigger"] == "https://api.device.example/v1/login"
        }),
        "controls={controls:?}"
    );
    assert!(
        revelations
            .iter()
            .any(|revelation| revelation["kind"] == "runtime-to-device-control-plane"),
        "revelations={revelations:?}"
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(
        report["leads"]
            .as_array()
            .is_some_and(|leads| leads.iter().any(|lead| {
                lead["family"] == "device-command-authority"
                    && lead["symbol"]
                        .as_str()
                        .is_some_and(|symbol| symbol.contains("package:deviceapp/"))
            })),
        "report={report:?}"
    );
}

#[test]
fn android_explain_reports_flutter_runtime_sections() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("config.armeabi_v7a.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("flutter-runtime.semantic.json");
    write_flutter_runtime_base_apk(&base_apk, "com.example.deviceapp");
    write_flutter_runtime_split_apk(&split_apk);
    write_jadx_flutter_sparse_tree(&jadx_root);

    let discover = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(discover.status.success(), "{discover:?}");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "explain",
            "--semantic-bundle",
            bundle_out.to_str().expect("bundle path"),
        ])
        .output()
        .expect("android explain runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.contains("runtime_dart_packages: 4"), "{stdout}");
    assert!(
        stdout.contains("package:deviceapp/bluetooth.dart"),
        "{stdout}"
    );
    assert!(stdout.contains("role=local-device-control"), "{stdout}");
    assert!(
        stdout.contains("package:deviceapp/pages/login.dart"),
        "{stdout}"
    );
    assert!(stdout.contains("role=account-auth"), "{stdout}");
    assert!(stdout.contains("runtime_plugins: 2"), "{stdout}");
    assert!(stdout.contains("flutter_blue_plus"), "{stdout}");
    assert!(stdout.contains("runtime_http_endpoints: 2"), "{stdout}");
    assert!(
        stdout.contains("https://api.device.example/v1/login"),
        "{stdout}"
    );
    assert!(stdout.contains("runtime_chains: 3"), "{stdout}");
    assert!(stdout.contains("local-device-control"), "{stdout}");
    assert!(stdout.contains("account-auth"), "{stdout}");
}

#[test]
fn android_explain_compresses_verbose_embedded_web_runtime_chain() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("config.armeabi_v7a.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("flutter-runtime.semantic.json");
    write_flutter_runtime_base_apk(&base_apk, "com.example.deviceapp");
    write_flutter_runtime_verbose_webview_split_apk(&split_apk);
    write_jadx_flutter_sparse_tree(&jadx_root);

    let discover = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(discover.status.success(), "{discover:?}");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "explain",
            "--semantic-bundle",
            bundle_out.to_str().expect("bundle path"),
        ])
        .output()
        .expect("android explain runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.contains("- embedded-web-content"), "{stdout}");
    assert!(stdout.contains("webview_flutter_android"), "{stdout}");
    assert!(stdout.contains("plugins.flutter.io/webview"), "{stdout}");
    assert!(stdout.contains("WebViewHostApi.loadUrl"), "{stdout}");
    assert!(stdout.contains("+"), "{stdout}");
    assert!(
        !stdout.contains("CustomViewCallbackFlutterApi.create"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("WebChromeClientFlutterApi.onConsoleMessage"),
        "{stdout}"
    );
}

#[test]
fn android_chains_json_returns_runtime_path_for_flutter_fixture() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("config.armeabi_v7a.apk");
    let jadx_root = dir.path().join("jadx");
    write_flutter_runtime_base_apk(&base_apk, "com.example.deviceapp");
    write_flutter_runtime_split_apk(&split_apk);
    write_jadx_flutter_sparse_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "chains",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--entry",
            "bluetooth",
            "--sink",
            "main.lua",
            "--json",
        ])
        .output()
        .expect("android chains runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["path_found"], true, "report={report:?}");
    let steps = report["steps"].as_array().expect("steps array");
    assert!(steps.iter().any(|step| {
        step["label"]
            .as_str()
            .is_some_and(|label| label.contains("package:deviceapp/bluetooth.dart"))
    }));
    assert!(steps.iter().any(|step| {
        step["label"]
            .as_str()
            .is_some_and(|label| label.contains("assets/lua_scripts/main.lua"))
    }));
}

#[test]
fn android_chains_rejects_informational_runtime_endpoint_to_bluetooth() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("config.armeabi_v7a.apk");
    let jadx_root = dir.path().join("jadx");
    write_flutter_runtime_base_apk(&base_apk, "com.example.deviceapp");
    write_flutter_runtime_chain_stress_split_apk(&split_apk);
    write_jadx_flutter_sparse_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "chains",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--entry",
            "privacy-policy",
            "--sink",
            "bluetooth",
            "--json",
        ])
        .output()
        .expect("android chains runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["status"], "no-path", "report={report:?}");
    assert_eq!(report["path_found"], false, "report={report:?}");
}

#[test]
fn android_chains_rejects_firmware_to_bluetooth_without_explicit_bridge() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("config.armeabi_v7a.apk");
    let jadx_root = dir.path().join("jadx");
    write_flutter_runtime_base_apk(&base_apk, "com.example.deviceapp");
    write_flutter_runtime_chain_stress_split_apk(&split_apk);
    write_jadx_flutter_sparse_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "chains",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--entry",
            "firmware",
            "--sink",
            "bluetooth",
            "--json",
        ])
        .output()
        .expect("android chains runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["status"], "no-path", "report={report:?}");
    assert_eq!(report["path_found"], false, "report={report:?}");
}

#[test]
fn android_chains_prefers_account_auth_runtime_cluster() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("config.armeabi_v7a.apk");
    let jadx_root = dir.path().join("jadx");
    write_flutter_runtime_base_apk(&base_apk, "com.example.deviceapp");
    write_flutter_runtime_chain_stress_split_apk(&split_apk);
    write_jadx_flutter_sparse_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "chains",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--entry",
            "login",
            "--sink",
            "signout",
            "--json",
        ])
        .output()
        .expect("android chains runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["path_found"], true, "report={report:?}");
    let steps = report["steps"].as_array().expect("steps array");
    assert!(steps.iter().any(|step| {
        step["label"].as_str().is_some_and(|label| {
            label.contains("runtime-account-auth") || label.contains("runtime-role-cluster")
        })
    }));
    assert!(steps.iter().all(|step| {
        step["label"]
            .as_str()
            .is_none_or(|label| !label.contains("runtime-to-device-control-plane"))
    }));
    assert!(steps.iter().all(|step| {
        step["label"]
            .as_str()
            .is_none_or(|label| !label.contains("flutter-runtime"))
    }));
}

#[test]
fn android_chains_keeps_local_device_runtime_cluster_for_bluetooth_to_main_lua() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("config.armeabi_v7a.apk");
    let jadx_root = dir.path().join("jadx");
    write_flutter_runtime_base_apk(&base_apk, "com.example.deviceapp");
    write_flutter_runtime_chain_stress_split_apk(&split_apk);
    write_jadx_flutter_sparse_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "chains",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--entry",
            "bluetooth",
            "--sink",
            "main.lua",
            "--json",
        ])
        .output()
        .expect("android chains runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["path_found"], true, "report={report:?}");
    let steps = report["steps"].as_array().expect("steps array");
    assert!(steps.iter().any(|step| {
        step["label"].as_str().is_some_and(|label| {
            label.contains("local-device-runtime-control") || label.contains("runtime-role-cluster")
        })
    }));
}

#[test]
fn android_discover_suppresses_flutter_runtime_noise_families() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let split_apk = dir.path().join("config.armeabi_v7a.apk");
    let jadx_root = dir.path().join("jadx");
    write_flutter_runtime_base_apk(&base_apk, "com.example.deviceapp");
    write_flutter_runtime_split_apk(&split_apk);
    write_jadx_flutter_sparse_tree_with_noise(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--splits",
            split_apk.to_str().expect("split path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-mode",
            "default",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let leads = report["leads"].as_array().expect("leads array");

    assert!(
        leads.iter().any(|lead| {
            lead["family"] == "device-command-authority"
                && lead["symbol"]
                    .as_str()
                    .is_some_and(|symbol| symbol.contains("package:deviceapp/bluetooth.dart"))
        }),
        "report={report:?}"
    );
    assert!(
        leads
            .iter()
            .all(|lead| lead["family"] != "binder-native-boundary"),
        "report={report:?}"
    );
    assert!(
        leads
            .iter()
            .all(|lead| lead["family"] != "webview-bridge-uri"),
        "report={report:?}"
    );
}

#[test]
fn android_discover_zero_lead_runtime_handoff_skips_manifest_and_reports_diagnostics() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let runtime_manifest = dir.path().join("runtime.json");
    fs::create_dir_all(jadx_root.join("sources/com/example")).expect("jadx dir");
    fs::write(
        jadx_root.join("sources/com/example/Placeholder.java"),
        "package com.example; class Placeholder {}",
    )
    .expect("placeholder");
    write_test_apk(&base_apk, false);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--runtime-manifest-out",
            runtime_manifest.to_str().expect("runtime manifest"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    assert!(
        !runtime_manifest.exists(),
        "runtime manifest should be skipped"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report.get("lead_count").and_then(Value::as_u64), Some(0));
    let warnings = report
        .get("warnings")
        .and_then(Value::as_array)
        .expect("warnings array");
    assert!(warnings.iter().any(|warning| {
        warning
            .as_str()
            .is_some_and(|value| value.contains("no leads available for runtime handoff"))
    }));
    let message = report
        .get("message")
        .and_then(Value::as_str)
        .expect("message");
    assert!(message.contains("No leads:"));
    assert!(message.contains("control_surface_count="));
    assert!(message.contains("trust_boundary_count="));
    assert!(message.contains("JADX output contains decompiled Java sources"));
}

#[test]
fn android_discover_derived_bundle_uses_manifest_package_and_emits_manifest_and_api_surfaces() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("surface.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("surface.semantic.json");
    write_surface_manifest_apk(&base_apk);
    write_jadx_sparse_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(
        report
            .get("lead_count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count >= 1),
        "{report}"
    );

    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    assert_eq!(
        bundle
            .get("target")
            .and_then(|target| target.get("package_name"))
            .and_then(Value::as_str),
        Some("com.example.surface")
    );
    assert!(bundle
        .get("control_surfaces")
        .and_then(Value::as_array)
        .is_some_and(|surfaces| surfaces.iter().any(|surface| {
            surface
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "manifest-exported-component")
        })));
    assert!(bundle
        .get("transport_surfaces")
        .and_then(Value::as_array)
        .is_some_and(|surfaces| surfaces.iter().any(|surface| {
            surface
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "provider-uri-access")
        })));
    assert!(bundle
        .get("facts")
        .and_then(Value::as_array)
        .is_some_and(|facts| facts.iter().any(|fact| {
            fact.get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "android-api.start-activity")
        })));
}

#[test]
fn android_discover_derived_bundle_lifts_mesh_protocol_source_semantics() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("mesh-protocol.semantic.json");
    write_test_apk(&base_apk, false);
    write_jadx_mesh_protocol_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");

    assert!(bundle["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .any(|fact| {
            fact["kind"] == "source.package-family"
                && fact["subject"] == "weave"
                && fact["attributes"]["sample"] == "com.example.weave.DeviceManager"
        }));
    assert!(bundle["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .any(|fact| {
            fact["kind"] == "source.import-family"
                && fact["subject"] == "grpc"
                && fact["attributes"]["sample"] == "io.grpc.Status"
        }));
    assert!(bundle["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .any(|fact| fact["kind"] == "source.protocol-family" && fact["subject"] == "weave"));
    assert!(bundle["symbol_identities"]
        .as_array()
        .expect("symbols array")
        .iter()
        .any(|symbol| symbol["qualified_name"]
            == "com.example.weave.DeviceManager.WeaveDeviceManager.onDeviceEnumerationResponse"));
    assert!(bundle["native_semantics"]
        .as_array()
        .expect("native semantics array")
        .iter()
        .any(|semantic| {
            semantic["kind"] == "java-load-library"
                && semantic["library_name"] == "WeaveDeviceManager"
        }));
    assert!(bundle["transport_surfaces"]
        .as_array()
        .expect("transport surfaces array")
        .iter()
        .any(|surface| surface["kind"] == "rpc-grpc"));
    let revelations = bundle["revelations"].as_array().expect("revelations array");
    assert!(
        revelations
            .iter()
            .any(|revelation| revelation["kind"] == "jni-security-boundary"),
        "missing revelation kind jni-security-boundary; got {revelations:?}"
    );
    assert!(
        !revelations
            .iter()
            .any(|revelation| revelation["kind"] == "weave-matter-bridge"),
        "weave-matter-bridge should require Matter-scoped evidence; got {revelations:?}"
    );
}

#[test]
fn android_discover_derived_bundle_lifts_unitree_control_plane_semantics() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("unitree-like.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.unitree.doggo2");
    write_jadx_unitree_control_plane_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");
    let controls = bundle["control_surfaces"]
        .as_array()
        .expect("control surfaces array");
    let subsystems = bundle["subsystems"].as_array().expect("subsystems array");
    let revelations = bundle["revelations"].as_array().expect("revelations array");

    for (kind, subject) in [
        ("role.command-envelope", "rt/api/sport/request"),
        ("role.session-offer", "session-token"),
        ("role.local-device-control", "UUID_SERVER"),
        ("role.account-device-binding", "oauth/bind"),
    ] {
        assert!(
            facts
                .iter()
                .any(|fact| fact["kind"] == kind && fact["subject"] == subject),
            "missing fact {kind}={subject}; got {facts:?}"
        );
    }

    for kind in [
        "web-command-bridge",
        "remote-command-dispatch",
        "local-device-control-surface",
        "account-device-bind-flow",
    ] {
        assert!(
            controls.iter().any(|surface| surface["kind"] == kind),
            "missing control surface {kind}; got {controls:?}"
        );
    }

    for kind in [
        "web-command-bridge",
        "session-command-control",
        "local-device-control",
        "account-device-binding",
    ] {
        assert!(
            subsystems.iter().any(|subsystem| subsystem["kind"] == kind),
            "missing subsystem {kind}; got {subsystems:?}"
        );
    }

    for kind in ["web-to-command-plane", "account-to-device-authority-plane"] {
        assert!(
            revelations
                .iter()
                .any(|revelation| revelation["kind"] == kind),
            "missing revelation {kind}; got {revelations:?}"
        );
    }
}

#[test]
fn android_discover_enumerates_javascript_interface_methods_and_sinks() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("js-bridge.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.unitree.doggo2");
    write_jadx_unitree_control_plane_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let controls = bundle["control_surfaces"]
        .as_array()
        .expect("control surfaces array");

    for (method_name, sink_note) in [
        ("webSendRTCSessionDescription", "eventbus-post"),
        ("webSendCmdRes", "command-dispatch"),
        ("webSendHttpRequest", "http-request"),
        ("webSaveProgramData", "file-write"),
    ] {
        assert!(
            controls.iter().any(|surface| {
                surface["kind"] == "javascript-interface-method"
                    && surface["trigger"]
                        .as_str()
                        .is_some_and(|trigger| trigger.contains(method_name))
                    && surface["notes"]
                        .as_array()
                        .is_some_and(|notes| notes.iter().any(|note| note == sink_note))
            }),
            "missing javascript-interface-method surface for {method_name} with sink {sink_note}; got {controls:?}"
        );
    }
}

#[test]
fn android_discover_derived_bundle_requires_positive_transport_evidence() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("transport-truth.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.unitree.doggo2");
    write_jadx_unitree_transport_truth_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");
    let transports = bundle["transport_surfaces"]
        .as_array()
        .expect("transport surfaces array");
    let controls = bundle["control_surfaces"]
        .as_array()
        .expect("control surfaces array");
    let revelations = bundle["revelations"].as_array().expect("revelations array");

    assert!(
        !facts.iter().any(|fact| {
            fact["kind"] == "source.protocol-family"
                && (fact["subject"] == "grpc" || fact["subject"] == "weave")
        }),
        "unexpected weak protocol families: {facts:?}"
    );
    assert!(
        !facts.iter().any(|fact| {
            fact["kind"] == "source.import-family"
                && (fact["subject"] == "grpc"
                    || fact["subject"] == "mqtt"
                    || fact["subject"] == "weave")
        }),
        "unexpected weak import families: {facts:?}"
    );
    assert!(
        !transports
            .iter()
            .any(|surface| surface["kind"] == "mqtt-marker" || surface["kind"] == "rpc-grpc"),
        "unexpected weak transport surfaces: {transports:?}"
    );
    assert!(
        !controls
            .iter()
            .any(|surface| surface["kind"] == "weave-security-plane"),
        "unexpected weak weave control plane: {controls:?}"
    );
    for kind in ["jni-security-boundary", "weave-matter-bridge"] {
        assert!(
            !revelations
                .iter()
                .any(|revelation| revelation["kind"] == kind),
            "unexpected revelation {kind}: {revelations:?}"
        );
    }
}

#[test]
fn android_discover_does_not_overclaim_transport_protocols_for_unitree_like_control_plane() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("unitree-transport.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.unitree.doggo2");
    write_jadx_unitree_control_plane_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");
    let transports = bundle["transport_surfaces"]
        .as_array()
        .expect("transport surfaces array");
    let controls = bundle["control_surfaces"]
        .as_array()
        .expect("control surfaces array");

    for subject in ["mqtt", "grpc", "weave"] {
        assert!(
            !facts.iter().any(|fact| {
                fact["kind"] == "source.protocol-family" && fact["subject"] == subject
            }),
            "unexpected protocol family {subject}; got {facts:?}"
        );
    }

    for kind in ["mqtt-marker", "rpc-grpc"] {
        assert!(
            !transports.iter().any(|surface| surface["kind"] == kind),
            "unexpected transport surface {kind}; got {transports:?}"
        );
    }

    assert!(
        !controls
            .iter()
            .any(|surface| surface["kind"] == "weave-security-plane"),
        "unexpected weave control surface; got {controls:?}"
    );
}

#[test]
fn android_discover_exposes_device_command_and_device_binding_leads() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    write_manifest_apk_with_package(&base_apk, "com.unitree.doggo2");
    write_jadx_unitree_control_plane_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let leads = report["leads"].as_array().expect("leads array");

    let command_lead = leads
        .iter()
        .find(|lead| lead["family"] == "device-command-authority")
        .unwrap_or_else(|| panic!("missing device command lead; got {leads:?}"));
    assert!(
        leads.iter().any(|lead| {
            lead["family"] == "device-command-authority"
                && lead["symbol"]
                    .as_str()
                    .is_some_and(|symbol| symbol.contains("AndroidInterface"))
        }),
        "device command lead lost its observed bridge symbol; got {leads:?}"
    );
    assert!(
        command_lead["matched_roles"]
            .as_array()
            .is_some_and(|roles| roles
                .iter()
                .any(|role| role["role"] == "authority-subsystem")),
        "device command lead lacks subsystem evidence; got {command_lead:?}"
    );
    assert!(
        command_lead["expected_proof_signal"]
            .as_array()
            .is_some_and(|signals| signals
                .iter()
                .any(|signal| signal["kind"] == "command-dispatch")),
        "device command lead lacks command proof signal; got {command_lead:?}"
    );
    assert!(
        command_lead["suggested_trigger_recipe"]
            .as_array()
            .is_some_and(|steps| steps.iter().any(|step| step["kind"] == "command-envelope")),
        "device command lead lacks observed command-envelope detail; got {command_lead:?}"
    );
    assert!(
        !leads.iter().any(|lead| {
            lead["family"] == "device-command-authority"
                && lead["symbol"]
                    .as_str()
                    .is_some_and(|symbol| symbol.contains("backToApp"))
        }),
        "device command lead should not collapse to benign bridge helpers; got {leads:?}"
    );
    let binding_lead = leads
        .iter()
        .find(|lead| lead["family"] == "device-binding-authority")
        .unwrap_or_else(|| panic!("missing device binding lead; got {leads:?}"));
    // The concrete binding class is no longer named by the lead symbol: it was
    // previously attributed only through its `com.unitree.login` package prefix.
    // Provenance is observed file evidence, so it must still reach the source.
    assert!(
        binding_lead["provenance_summary"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| entry
                .as_str()
                .is_some_and(|path| path.contains("LoginApi.java")))),
        "device binding lead lost provenance to the observed login source; got {binding_lead:?}"
    );
    assert!(
        binding_lead["suggested_trigger_recipe"]
            .as_array()
            .is_some_and(|steps| steps.iter().any(|step| step["detail"] == "oauth/bind")),
        "device binding lead lacks observed bind detail; got {binding_lead:?}"
    );
}

#[test]
fn android_discover_extracts_static_secrets_and_crypto_material() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("security-constants.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.example.security");
    write_jadx_security_constants_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");

    for (kind, subject) in [
        ("security.static-secret", "APP_SIGN_SECRET"),
        ("security.public-key", "PUBLIC_KEY"),
        ("security.symmetric-key-material", "IV"),
        ("security.symmetric-key-material", "secretKey"),
        ("security.symmetric-key-material", "keyBytes"),
        ("security.symmetric-key-material", "zero-key-fallback"),
        ("security.default-credential", "DEFAULT_AP_PWD"),
        ("network.static-endpoint", "DOG_ADDRESS"),
        ("network.static-endpoint", "UDP_IP"),
        ("network.static-endpoint", "UDP_PORT"),
    ] {
        assert!(
            facts
                .iter()
                .any(|fact| fact["kind"] == kind && fact["subject"] == subject),
            "missing fact {kind}={subject}; got {facts:?}"
        );
    }
}

#[test]
fn android_discover_suppresses_third_party_security_constant_noise_in_default_mode() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("security-constants-filtered.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.example.security");
    write_jadx_security_constants_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");

    assert!(
        !facts.iter().any(|fact| {
            (fact["kind"] == "security.static-secret" && fact["subject"] == "VISIBILITY_SECRET")
                || (fact["kind"] == "network.static-endpoint"
                    && fact["subject"] == "IMPORTANCE_DEFAULT")
                || (fact["kind"] == "security.public-key" && fact["subject"] == "PUBLIC_KEY_PINS")
        }),
        "unexpected third-party constant facts leaked into default mode: {facts:?}"
    );
}

#[test]
fn android_discover_extracts_tls_and_storage_security_facts() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("tls-storage.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.example.security");
    write_jadx_tls_storage_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");

    for (kind, subject) in [
        (
            "tls.hostname-verification-disabled",
            "HostnameVerifier#verify",
        ),
        ("tls.weak-trust-manager", "X509TrustManager"),
        ("storage.plaintext-token-store", "KEY_SP_TOKEN"),
        ("storage.plaintext-token-store", "KEY_SP_REFRESH_TOKEN"),
        ("storage.available-encryption-unused", "MMKV.defaultMMKV"),
    ] {
        assert!(
            facts
                .iter()
                .any(|fact| fact["kind"] == kind && fact["subject"] == subject),
            "missing fact {kind}={subject}; got {facts:?}"
        );
    }
}

#[test]
fn android_discover_extracts_retrofit_and_http_api_surfaces() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("http-api.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.example.api");
    write_jadx_http_api_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let controls = bundle["control_surfaces"]
        .as_array()
        .expect("control surfaces array");
    let facts = bundle["facts"].as_array().expect("facts array");

    for (kind, trigger) in [
        ("http-api-endpoint", "oauth/token"),
        ("http-api-endpoint", "oauth/bind"),
        ("http-api-endpoint", "device/bind"),
        ("signaling-endpoint", "webrtc/connect"),
        ("http-api-endpoint", "firmware/package/download"),
    ] {
        assert!(
            controls
                .iter()
                .any(|surface| surface["kind"] == kind && surface["trigger"] == trigger),
            "missing {kind} surface for {trigger}; got {controls:?}"
        );
    }

    assert!(
        controls.iter().any(|surface| {
            surface["kind"] == "http-api-endpoint"
                && surface["trigger"] == "{path}"
                && surface["notes"]
                    .as_array()
                    .is_some_and(|notes| notes.iter().any(|note| note == "dynamic-path"))
        }),
        "missing dynamic path endpoint; got {controls:?}"
    );

    for (kind, subject) in [
        ("http.auth-header", "AppSign"),
        ("http.auth-header", "Token"),
        ("http.auth-header", "AppNonce"),
        ("http.dynamic-path", "{path}"),
    ] {
        assert!(
            facts
                .iter()
                .any(|fact| fact["kind"] == kind && fact["subject"] == subject),
            "missing fact {kind}={subject}; got {facts:?}"
        );
    }
}

#[test]
fn android_discover_extracts_command_catalogs_and_envelope_fields() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("command-catalog.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.example.commands");
    write_jadx_command_catalog_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");

    for subject in [
        "DogApiId.BASH_RUNNER",
        "DogApiId.CLEAR_DATA",
        "DogApiId.PROGRAM_ACTUATOR_SET",
        "BaseRunner.clear_data",
        "BaseRunner.upload_program",
        "BaseRunner.bash_runner",
    ] {
        assert!(
            facts.iter().any(|fact| {
                fact["kind"] == "role.command-catalog-entry" && fact["subject"] == subject
            }),
            "missing command catalog entry {subject}; got {facts:?}"
        );
    }

    for subject in ["topic", "api_id", "id", "data"] {
        assert!(
            facts.iter().any(|fact| {
                fact["kind"] == "role.command-envelope-field" && fact["subject"] == subject
            }),
            "missing command envelope field {subject}; got {facts:?}"
        );
    }
}

#[test]
fn android_chains_json_returns_non_empty_path_for_unitree_like_command_chain() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    write_manifest_apk_with_package(&base_apk, "com.unitree.doggo2");
    write_jadx_unitree_chain_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "chains",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--entry",
            "web-to-command-plane",
            "--sink",
            "bashrunner",
            "--json",
        ])
        .output()
        .expect("android chains runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["path_found"], true, "report={report:?}");
    let steps = report["steps"].as_array().expect("steps array");
    assert!(!steps.is_empty(), "report={report:?}");
    assert!(steps.iter().any(|step| {
        step["label"]
            .as_str()
            .is_some_and(|label| label.contains("web-to-command-plane"))
    }));
    assert!(steps.iter().any(|step| {
        step["label"]
            .as_str()
            .is_some_and(|label| label.contains("BaseRunner.bash_runner"))
    }));
    assert!(steps.iter().any(|step| {
        step["label"]
            .as_str()
            .is_some_and(|label| label.contains("remote-command-dispatch"))
    }));
}

#[test]
fn android_discover_detects_tls_misuse_and_plaintext_token_storage() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("tls-storage.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.example.store");
    write_jadx_tls_storage_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");

    for (kind, subject) in [
        (
            "tls.hostname-verification-disabled",
            "HostnameVerifier#verify",
        ),
        ("tls.weak-trust-manager", "X509TrustManager"),
        ("storage.plaintext-token-store", "KEY_SP_TOKEN"),
        ("storage.plaintext-token-store", "KEY_SP_REFRESH_TOKEN"),
        ("storage.available-encryption-unused", "MMKV.defaultMMKV"),
    ] {
        assert!(
            facts
                .iter()
                .any(|fact| fact["kind"] == kind && fact["subject"] == subject),
            "missing fact {kind}={subject}; got {facts:?}"
        );
    }
}

#[test]
fn android_discover_extracts_ble_security_semantics() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("ble-security.semantic.json");
    write_manifest_apk_with_package(&base_apk, "com.example.ble");
    write_jadx_ble_security_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");

    for (kind, subject) in [
        ("ble.characteristic-uuid", "UUID_SERVER"),
        ("ble.characteristic-uuid", "UUID_NOTI"),
        ("ble.crypto-mode", "AES/CFB128/NoPadding"),
        ("ble.crypto-mode", "AES/GCM/NoPadding"),
        ("ble.session-key-derivation", "session_key"),
        ("role.local-device-bootstrap", "local-device-bootstrap"),
    ] {
        assert!(
            facts
                .iter()
                .any(|fact| fact["kind"] == kind && fact["subject"] == subject),
            "missing BLE fact {kind}={subject}; got {facts:?}"
        );
    }
}

#[test]
fn android_discover_derived_bundle_filters_boring_method_symbols() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("noisy.semantic.json");
    write_test_apk(&base_apk, false);
    write_jadx_noisy_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let symbols = bundle["symbol_identities"]
        .as_array()
        .expect("symbols array");

    assert!(symbols.iter().any(|symbol| {
        symbol["qualified_name"] == "com.example.noisy.NoisyManager.onDeviceEnumerationResponse"
    }));
    assert!(!symbols
        .iter()
        .any(|symbol| { symbol["qualified_name"] == "com.example.noisy.NoisyManager.getStatus" }));
    assert!(!symbols.iter().any(|symbol| {
        symbol["qualified_name"] == "com.example.noisy.NoisyManager.helperMethod"
    }));
    let revelations = bundle["revelations"].as_array().expect("revelations array");
    for kind in [
        "commissioning-plane",
        "fabric-authority-plane",
        "key-export-risk-plane",
        "weave-matter-bridge",
        "jni-security-boundary",
    ] {
        assert!(
            !revelations
                .iter()
                .any(|revelation| revelation["kind"] == kind),
            "unexpected revelation kind {kind}; got {revelations:?}"
        );
    }
    assert!(
        !bundle["correlations"]
            .as_array()
            .expect("correlations array")
            .iter()
            .any(|correlation| correlation["correlation_id"] == "corr-java-native-bridge"),
        "unexpected corr-java-native-bridge correlation; got {:?}",
        bundle["correlations"]
            .as_array()
            .expect("correlations array")
    );
}

#[test]
fn android_discover_derived_bundle_filters_weak_class_symbols() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("class-filter.semantic.json");
    write_test_apk(&base_apk, false);
    write_jadx_noisy_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let symbols = bundle["symbol_identities"]
        .as_array()
        .expect("symbols array");

    assert!(symbols
        .iter()
        .any(|symbol| { symbol["qualified_name"] == "com.example.noisy.NoisyManager" }));
    assert!(!symbols
        .iter()
        .any(|symbol| { symbol["qualified_name"] == "com.example.noisy.UtilityHelper" }));
}

#[test]
fn android_discover_dense_mode_emits_more_symbol_detail() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let default_bundle_out = dir.path().join("default.semantic.json");
    let dense_bundle_out = dir.path().join("dense.semantic.json");
    write_test_apk(&base_apk, false);
    write_jadx_noisy_tree(&jadx_root);

    let default_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            default_bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");
    assert!(default_output.status.success(), "{default_output:?}");

    let dense_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-mode",
            "dense",
            "--semantic-bundle-out",
            dense_bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");
    assert!(dense_output.status.success(), "{dense_output:?}");

    let default_bundle: Value =
        serde_json::from_slice(&fs::read(&default_bundle_out).expect("default bundle bytes"))
            .expect("default bundle");
    let dense_bundle: Value =
        serde_json::from_slice(&fs::read(&dense_bundle_out).expect("dense bundle bytes"))
            .expect("dense bundle");

    assert!(
        dense_bundle["symbol_identities"]
            .as_array()
            .expect("dense symbols")
            .len()
            > default_bundle["symbol_identities"]
                .as_array()
                .expect("default symbols")
                .len()
    );
    assert!(dense_bundle["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .any(|fact| fact["kind"] == "source.import" && fact["subject"] == "io.grpc.Status"));
}

#[test]
fn android_discover_derived_bundle_filters_irrelevant_import_facts() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("import-filter.semantic.json");
    write_test_apk(&base_apk, false);
    write_jadx_noisy_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");

    assert!(facts.iter().any(|fact| {
        fact["kind"] == "source.import-family"
            && fact["subject"] == "grpc"
            && fact["attributes"]["sample"] == "io.grpc.Status"
    }));
    assert!(!facts
        .iter()
        .any(|fact| { fact["kind"] == "source.import" && fact["subject"] == "java.util.Random" }));
    assert!(!facts
        .iter()
        .any(|fact| { fact["kind"] == "source.import" && fact["subject"] == "android.util.Log" }));
    assert!(!facts
        .iter()
        .any(|fact| { fact["kind"] == "source.import-family" && fact["subject"] == "java" }));
}

#[test]
fn android_discover_derived_bundle_ranks_endpoint_control_surfaces() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("endpoint-rank.semantic.json");
    write_test_apk(&base_apk, false);
    write_jadx_endpoint_rank_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let control_surfaces = bundle["control_surfaces"]
        .as_array()
        .expect("control surfaces array");

    assert!(control_surfaces.iter().any(|surface| {
        surface["kind"] == "endpoint-template"
            && surface["trigger"] == "/api/v1/devices/{sn}/live/openStream/start"
    }));
    assert!(control_surfaces.iter().any(|surface| {
        surface["kind"] == "endpoint-template"
            && surface["trigger"] == "/api/v1/users/devices/{sn}/bind/check"
    }));
    assert!(!control_surfaces.iter().any(|surface| {
        surface["kind"] == "endpoint-template" && surface["trigger"] == "/api/v1/hms/{hms}/faq"
    }));
    assert!(!control_surfaces.iter().any(|surface| {
        surface["kind"] == "endpoint-template"
            && surface["trigger"] == "/api/v1/devices/{sn}/maps/mapContentUpdate"
    }));
    assert!(!control_surfaces.iter().any(|surface| {
        surface["kind"] == "endpoint-template"
            && surface["trigger"] == "https://static.example/assets/pairing-code.webp"
    }));
    assert!(!control_surfaces.iter().any(|surface| {
        surface["kind"] == "endpoint-template"
            && surface["trigger"] == "deviceapp://devices/controller"
    }));
}

#[test]
fn android_discover_derived_bundle_lifts_commissioning_security_families() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    let bundle_out = dir.path().join("weave-deep.semantic.json");
    write_test_apk(&base_apk, false);
    write_jadx_weave_deep_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--semantic-bundle-out",
            bundle_out.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_out).expect("bundle bytes")).expect("bundle");
    let facts = bundle["facts"].as_array().expect("facts array");
    let control_surfaces = bundle["control_surfaces"]
        .as_array()
        .expect("control surfaces array");
    let security_families: Vec<&str> = facts
        .iter()
        .filter(|fact| fact["kind"] == "source.security-family")
        .map(|fact| fact["subject"].as_str().expect("security subject"))
        .collect();
    let protocol_families: Vec<&str> = facts
        .iter()
        .filter(|fact| fact["kind"] == "source.protocol-family")
        .map(|fact| fact["subject"].as_str().expect("protocol subject"))
        .collect();

    assert!(security_families.contains(&"pairing-code"));
    assert!(security_families.contains(&"fabric-membership"));
    assert!(security_families.contains(&"certificate"));
    assert!(security_families.contains(&"commissioning"));
    assert!(security_families.contains(&"access-token"));
    assert!(security_families.contains(&"key-export"));
    assert!(protocol_families.contains(&"weave"));
    assert!(bundle["control_surfaces"]
        .as_array()
        .expect("control surfaces array")
        .iter()
        .any(|surface| surface["kind"] == "weave-security-plane"));
    assert!(bundle["control_surfaces"]
        .as_array()
        .expect("control surfaces array")
        .iter()
        .any(|surface| surface["kind"] == "matter-commissioning-session"));
    assert!(control_surfaces
        .iter()
        .any(|surface| { surface["kind"] == "device-commissioning-flow" }));
    assert!(bundle["native_semantics"]
        .as_array()
        .expect("native semantics array")
        .iter()
        .any(|semantic| semantic["kind"] == "weave-key-export-native"));
    assert!(bundle["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .any(|fact| {
            fact["kind"] == "protocol.weave-key-export"
                && fact["provenance"].as_array().is_some_and(|provenance| {
                    provenance.iter().any(|entry| {
                        entry["artifact"]
                            .as_str()
                            .is_some_and(|artifact| artifact.contains("WeaveSecuritySupport.java"))
                    })
                })
        }));
    assert!(bundle["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .any(|fact| {
            fact["kind"] == "protocol.matter-commissioning"
                && fact["provenance"].as_array().is_some_and(|provenance| {
                    provenance.iter().any(|entry| {
                        entry["artifact"]
                            .as_str()
                            .is_some_and(|artifact| artifact.contains("SharedDeviceData.java"))
                    })
                })
        }));
    assert!(bundle["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .any(|fact| {
            fact["kind"] == "source.protocol-family"
                && fact["subject"] == "ble"
                && fact["provenance"].as_array().is_some_and(|provenance| {
                    provenance.iter().any(|entry| {
                        entry["artifact"]
                            .as_str()
                            .is_some_and(|artifact| artifact.contains("BleScanner.java"))
                    })
                })
        }));
    assert!(bundle["correlations"]
        .as_array()
        .expect("correlations array")
        .iter()
        .any(|correlation| correlation["kind"] == "weave-auth-fabric-key-export"));
    let subsystems = bundle["subsystems"].as_array().expect("subsystems array");
    assert!(
        subsystems.iter().any(|subsystem| {
            subsystem["kind"] == "weave-device-security"
                && subsystem["support_level"] == "Observed"
                && subsystem["package_prefixes"]
                    .as_array()
                    .is_some_and(|prefixes| prefixes.iter().any(|value| value == "nl.Weave"))
        }),
        "missing weave subsystem: {subsystems:?}"
    );
    assert!(
        subsystems.iter().any(|subsystem| {
            subsystem["kind"] == "matter-commissioning"
                && subsystem["package_prefixes"]
                    .as_array()
                    .is_some_and(|prefixes| {
                        prefixes.iter().any(|value| {
                            value == "com.example.matter"
                                || value == "com.example.matter.commissioning"
                        })
                    })
        }),
        "missing matter subsystem: {subsystems:?}"
    );
    assert!(
        subsystems.iter().any(|subsystem| {
            subsystem["kind"] == "ble-scanning"
                && subsystem["package_prefixes"]
                    .as_array()
                    .is_some_and(|prefixes| prefixes.iter().any(|value| value == "com.example.ble"))
        }),
        "missing ble subsystem: {subsystems:?}"
    );
    assert!(bundle["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .any(|fact| fact["kind"] == "source.protocol-family" && fact["subject"] == "ble"));
    let revelations = bundle["revelations"].as_array().expect("revelations array");
    for kind in [
        "commissioning-plane",
        "fabric-authority-plane",
        "key-export-risk-plane",
    ] {
        assert!(
            revelations
                .iter()
                .any(|revelation| revelation["kind"] == kind),
            "missing revelation kind {kind}; got {revelations:?}"
        );
    }
    assert!(
        revelations.iter().any(|revelation| {
            revelation["kind"] == "commissioning-plane"
                && revelation["subsystem_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|id| id == "subsystem-matter-commissioning"))
        }),
        "commissioning revelation missing subsystem scope: {revelations:?}"
    );
    assert!(
        revelations.iter().any(|revelation| {
            revelation["kind"] == "fabric-authority-plane"
                && revelation["subsystem_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|id| id == "subsystem-weave-device-security"))
        }),
        "fabric revelation missing subsystem scope: {revelations:?}"
    );
    assert!(
        revelations.iter().any(|revelation| {
            revelation["kind"] == "fabric-authority-plane"
                && revelation["subsystem_ids"].as_array().is_some_and(|ids| {
                    ids.len() == 1 && ids.iter().all(|id| id == "subsystem-weave-device-security")
                })
        }),
        "fabric revelation should stay narrow to weave subsystem: {revelations:?}"
    );
    assert!(
        revelations.iter().any(|revelation| {
            revelation["kind"] == "jni-security-boundary"
                && revelation["subsystem_ids"].as_array().is_some_and(|ids| {
                    ids.len() == 1 && ids.iter().all(|id| id == "subsystem-weave-device-security")
                })
        }),
        "jni revelation missing narrow weave scope: {revelations:?}"
    );
}

#[test]
fn android_discover_exposes_commissioning_fabric_authority_family() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    write_test_apk(&base_apk, false);
    write_jadx_weave_deep_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--family",
            "commissioning-fabric-authority",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(
        report
            .get("leads")
            .and_then(Value::as_array)
            .is_some_and(|leads| !leads.is_empty()),
        "{report:?}"
    );
    assert!(
        report
            .get("leads")
            .and_then(Value::as_array)
            .is_some_and(|leads| leads.iter().all(|lead| {
                lead.get("family")
                    .and_then(Value::as_str)
                    .is_some_and(|family| family == "commissioning-fabric-authority")
            })),
        "{report:?}"
    );
}

#[test]
fn android_discover_prefers_commissioning_fabric_leads_for_weave_deep_bundle() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    write_test_apk(&base_apk, false);
    write_jadx_weave_deep_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let first_lead = report
        .get("leads")
        .and_then(Value::as_array)
        .and_then(|leads| leads.first())
        .expect("first lead");
    assert_eq!(
        first_lead.get("family").and_then(Value::as_str),
        Some("commissioning-fabric-authority"),
        "{report:?}"
    );
    assert!(
        first_lead
            .get("symbol")
            .and_then(Value::as_str)
            .is_some_and(|symbol| {
                symbol.contains("WeaveDeviceManager")
                    || symbol.contains("DeviceManagerImpl")
                    || symbol.contains("MatterSetupProxyActivity")
            }),
        "{report:?}"
    );
    assert!(
        report
            .get("leads")
            .and_then(Value::as_array)
            .is_some_and(|leads| {
                leads
                    .iter()
                    .filter(|lead| {
                        lead.get("family")
                            .and_then(Value::as_str)
                            .is_some_and(|family| family == "commissioning-fabric-authority")
                    })
                    .count()
                    == 1
            }),
        "{report:?}"
    );
    assert!(
        first_lead
            .get("sibling_candidates")
            .and_then(Value::as_array)
            .is_some_and(|siblings| !siblings.is_empty()),
        "{report:?}"
    );
}

#[test]
fn android_discover_uses_apkanalyzer_fallback_for_binary_manifest_package_and_surfaces() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("binary.apk");
    let jadx_root = dir.path().join("jadx");
    let bin_dir = dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    fs::create_dir_all(jadx_root.join("sources/com/example")).expect("jadx dir");
    fs::write(
        jadx_root.join("sources/com/example/Placeholder.java"),
        "package com.example; class Placeholder { void go() { startActivity(null); } }",
    )
    .expect("placeholder");
    write_fake_apkanalyzer(&bin_dir, "com.example.binary");

    let file = std::fs::File::create(&base_apk).expect("create apk");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    zip.start_file("AndroidManifest.xml", opts)
        .expect("manifest entry");
    use std::io::Write as _;
    zip.write_all(b"AXML").expect("binary manifest bytes");
    zip.start_file("classes.dex", opts).expect("classes.dex");
    zip.write_all(b"dex").expect("dex bytes");
    zip.finish().expect("finish zip");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("apk path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--json",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        report.get("manifest_package_name").and_then(Value::as_str),
        Some("com.example.binary")
    );
    assert_eq!(
        report
            .get("semantic")
            .and_then(|semantic| semantic.get("target_package_name"))
            .and_then(Value::as_str),
        Some("com.example.binary")
    );
}

#[test]
fn android_inventory_uses_apkanalyzer_fallback_for_binary_manifest_details() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("binary.apk");
    let bin_dir = dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    write_fake_apkanalyzer(&bin_dir, "com.example.binary");

    let file = std::fs::File::create(&base_apk).expect("create apk");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    zip.start_file("AndroidManifest.xml", opts)
        .expect("manifest entry");
    use std::io::Write as _;
    zip.write_all(b"AXML").expect("binary manifest bytes");
    zip.start_file("classes.dex", opts).expect("classes.dex");
    zip.write_all(b"dex").expect("dex bytes");
    zip.finish().expect("finish zip");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "inventory",
            "--apk",
            base_apk.to_str().expect("apk path"),
            "--json",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .expect("android inventory runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let manifest = &report["containers"][0]["manifest"];
    assert_eq!(manifest["parse_status"], "Parsed");
    assert_eq!(manifest["package_name"], "com.example.binary");
    assert_eq!(manifest["debuggable"], true);
    assert_eq!(manifest["uses_cleartext_traffic"], true);
    assert!(
        manifest["requested_permissions"]
            .as_array()
            .is_some_and(|permissions| permissions
                .iter()
                .any(|p| p == "android.permission.INTERNET")),
        "manifest={manifest:?}"
    );
    assert!(
        manifest["components"]
            .as_array()
            .is_some_and(|components| !components.is_empty()),
        "manifest={manifest:?}"
    );
}

#[test]
fn android_discover_rejects_xapk_with_guidance() {
    let dir = tempdir().expect("tempdir");
    let xapk = dir.path().join("Unitree.xapk");
    fs::write(&xapk, b"placeholder").expect("write xapk");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            xapk.to_str().expect("xapk path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not accept .xapk directly"),
        "{stderr}"
    );
    assert!(stderr.contains("extract the XAPK"), "{stderr}");
}

#[test]
fn android_discover_rejects_embedded_apk_bundle_container_with_guidance() {
    let dir = tempdir().expect("tempdir");
    let outer_apk = dir.path().join("noah-frame.apk");
    write_embedded_apk_bundle_container(&outer_apk);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            outer_apk.to_str().expect("outer apk path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("embedded APK bundle"), "{stderr}");
    assert!(stderr.contains("extract"), "{stderr}");
    assert!(stderr.contains("--apk <base.apk>"), "{stderr}");
}

#[test]
fn android_discover_warns_when_top_k_exceeds_surfaced_leads() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let jadx_root = dir.path().join("jadx");
    write_manifest_apk_with_package(&base_apk, "com.unitree.doggo2");
    write_jadx_unitree_control_plane_tree(&jadx_root);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("base path"),
            "--jadx-root",
            jadx_root.to_str().expect("jadx root"),
            "--family",
            "device-command-authority",
            "--top-k",
            "5",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["lead_count"], 1);
    assert!(
        report["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| {
                warning.as_str().is_some_and(|text| {
                    text.contains("requested top_k=5 but only 1 leads surfaced")
                })
            })),
        "report={report:?}"
    );
}
