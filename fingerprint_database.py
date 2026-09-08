FINGERPRINTS = {

    # ========================================================
    # Fingerprint 1 - curl
    # ========================================================

    "cf9e882e7bc3f3e6f57a5d768f846dcd": {
        "application": "curl",
        "version": "8.21.0",
        "tls_stack": "Windows Schannel",
        "notes": "Observed during controlled curl.exe test"
    },


    # ========================================================
    # Fingerprint 2 - Python SSL
    # ========================================================

    "d7268fba5c8ebdc86121861931c04402": {
        "application": "Python SSL",
        "version": "Python 3.x",
        "tls_stack": "Python ssl / OpenSSL",
        "notes": "Previously observed during controlled Python TLS test"
    },


    # ========================================================
    # Fingerprint 3 - Python SSL / Current Environment
    # ========================================================

    "93c7d42c0df602fb91589311534831f5": {
        "application": "Python SSL",
        "version": "Python 3.12.1",
        "tls_stack": "Python ssl / OpenSSL 3.0.11",
        "notes": "Observed during controlled Python TLS test"
    },


    # ========================================================
    # Fingerprint 4 - Chrome
    # ========================================================

    "091f51a7a1c3a4504a224cc081ce9cee": {
        "application": "Chrome",
        "version": "Installed Chrome version",
        "tls_stack": "Chrome TLS stack",
        "notes": "Observed during controlled Chrome HTTPS test"
    },


    # ========================================================
    # Fingerprint 5 - Firefox
    # ========================================================

    "d03be5b7aa2a8e3c5cfbaa33ed8256da": {
        "application": "Firefox",
        "version": "Installed Firefox version",
        "tls_stack": "Firefox TLS stack",
        "notes": "Observed during controlled Firefox Private Window test"
    },


    # ========================================================
    # Fingerprint 6 - Microsoft Edge
    # ========================================================

    "4e9725a4a78a23a30c381b0e4169508c": {
        "application": "Microsoft Edge",
        "version": "Installed Edge version",
        "tls_stack": "Edge TLS stack",
        "notes": "Observed during controlled Microsoft Edge HTTPS test"
    }

}