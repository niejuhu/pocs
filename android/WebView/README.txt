[CVE-2012-6636] WebView任意代码执行漏洞
======================================

Scan: addjs.html

原理：
Android API 16以及之前的版本没有正确的限制对通过WebView.addJavascriptInterface导出的Java对象的访问，导致远程攻击这可以利用导出的Java对象以及Java反射API执行任意代码。targetSdkVersion<17并且通过addJavascriptInterface导出了Java对象的app会受到漏洞影响。

WebView.addJavascript用于在网页中导出Java对象供Js调用。一般使用方法：
    class JsObject {
        @JavascriptInterface
        public String toString() { return "injectedObject"; }
    }
    webView.addJavascriptInterface(new JsObject(), "injectedObject");
    webView.loadData("", "text/html", null);
    webView.loadUrl("javascript:alert(injectedObject.toString())");

在API 17以及之后的版本，只有带@JavascriptInterface Annotation的方法才能被Js代码调用。而之前的版本没有这个限制，Js可以通过调用导出对象的其他方法。远程攻击者可以在网页中嵌入恶意Js代码，通过反射在应用程序进程环境中执行任意代码。一般攻击方法：
    <script>
    function execute(cmdArgs)
    {
        return js2java.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec(cmdArgs);
    }
    …
    </script>


修复：
Android API 17及以后版本修复了此漏洞：（WebViewClassic.java)
     @Override
     public void addJavascriptInterface(Object object, String name) {
+
         if (object == null) {
             return;
         }
         WebViewCore.JSInterfaceData arg = new WebViewCore.JSInterfaceData();
+
         arg.mObject = object;
         arg.mInterfaceName = name;
+
+        // starting with JELLY_BEAN_MR1, annotations are mandatory for enabling access to
+        // methods that are accessible from JS.
+        if (mContext.getApplicationInfo().targetSdkVersion >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
+            arg.mRequireAnnotation = true;
+        } else {
+            arg.mRequireAnnotation = false;
+        }
         mWebViewCore.sendMessage(EventHub.ADD_JS_INTERFACE, arg);
     }
 

UXSS 1
=======

Poc: xss/x1.html
See https://code.google.com/p/chromium/issues/detail?id=117550


UXSS 2
=======

Poc: xss/x2.html 加载对象时没有检查javascript安全策略
See https://code.google.com/p/chromium/issues/detail?id=98053


UXSS 3
=======

Poc: xss/x3.html 起始NULL字节导致将url判断为非javascript，因而忽略了安全策略
See https://code.google.com/p/chromium/issues/detail?id=37383


UXSS 4
======

Poc: xss/x4.html 
See https://code.google.com/p/chromium/issues/detail?id=90222


UXSS 5
======

Poc: xss/x5.html webkit只检查location属性url的安全策略，忽略了baseURL
See https://code.google.com/p/chromium/issues/detail?id=143437
