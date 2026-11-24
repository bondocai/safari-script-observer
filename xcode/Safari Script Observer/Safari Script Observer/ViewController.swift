//
//  ViewController.swift
//  Safari Script Observer
//
//  The app's window: first-run setup steps. Shows whether the extension is on
//  (refreshed whenever the app comes back to the front) and opens Safari's
//  Extensions settings without quitting, so the user can return to the steps.
//

import Cocoa
import SafariServices
import WebKit

let extensionBundleIdentifier = "com.example.SafariScriptObserver.Extension"

class ViewController: NSViewController, WKNavigationDelegate, WKScriptMessageHandler {

    @IBOutlet var webView: WKWebView!
    private var timer: Timer?
    private var wasOff = false

    override func viewDidLoad() {
        super.viewDidLoad()
        self.webView.navigationDelegate = self
        self.webView.configuration.userContentController.add(self, name: "controller")
        self.webView.loadFileURL(Bundle.main.url(forResource: "Main", withExtension: "html")!,
                                 allowingReadAccessTo: Bundle.main.resourceURL!)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        refreshState()
        // Watch while the window is open: the moment the user ticks the extension in
        // Safari's settings, this window steps aside and Safari's own setup page
        // (opened by the extension) takes over. One screen at a time.
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.refreshState() }
    }

    private func refreshState() {
        SFSafariExtensionManager.getStateOfSafariExtension(withIdentifier: extensionBundleIdentifier) { state, error in
            DispatchQueue.main.async {
                guard error == nil, let state else {
                    self.webView.evaluateJavaScript("show(null)")
                    return
                }
                self.webView.evaluateJavaScript("show(\(state.isEnabled), \(self.wasOff))")
                if !state.isEnabled {
                    self.wasOff = true
                } else if self.wasOff {
                    // Just turned on: hand over to Safari.
                    self.timer?.invalidate()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { NSApplication.shared.terminate(nil) }
                }
            }
        }
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        switch message.body as? String {
        case "open-preferences":
            SFSafariApplication.showPreferencesForExtension(withIdentifier: extensionBundleIdentifier) { _ in }
        case "quit":
            NSApplication.shared.terminate(nil)
        default:
            break
        }
    }
}
