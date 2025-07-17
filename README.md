# MagicConfigurationEncryptor

**MagicConfigurationEncryptor** is a browser-based tool for encrypting and decrypting YAML configuration files using AES-256 encryption. It supports recursive encryption of deeply nested YAML structures and includes an option to replace sensitive values with environment variable placeholders for enhanced security.

---

## ✨ Features

- 🔐 AES encryption (CBC mode with Pkcs7 padding)
- 🔁 Recursive support for nested YAML structures (objects and arrays)
- 🔀 Two encryption modes:
  - Direct encryption
  - Encryption with `${ENV_VAR}` placeholders
- 🧩 Multi-level property targeting
- 🧪 User-friendly HTML + JavaScript interface
- ⚙️ Environment variable export script generator (Linux/macOS or Windows)
- 🔑 Built-in 32-digit hex key generator

---

## 🖥️ Interface

The interface consists of two main panels:

| YAML Input (Left) | YAML Output (Right) |
|-------------------|---------------------|
| Raw YAML configuration to process | Encrypted or decrypted result |

---

## 🚀 How to Use

1. Open `index.html` in your browser.
2. Enter a 32-digit hex encryption key (or click **Generate Random Key**).
3. Paste your YAML content in the left panel.
4. Specify the YAML paths to encrypt (one per line).
5. Select the desired mode:
   - Encrypt
   - Encrypt with Placeholder
   - Decrypt
6. The result will appear in the right panel.
7. If using placeholder mode, a script to set environment variables will also be generated.

---

## 🌱 Environment Variable Mapping

Environment variable names are auto-generated based on the YAML property path. For example:

```yaml
database:
  password: secret123
````

Will generate:

```env
MYAPP_DATABASE_PASSWORD=EncryptedValue
```

---

## 💻 Export Script Output

You can choose the target operating system to generate the appropriate script:

```bash
# Linux/macOS
export MYAPP_DATABASE_PASSWORD=...
export MYAPP_SESSIONS_SECRET=...
```

```cmd
:: Windows CMD
set MYAPP_DATABASE_PASSWORD=...
set MYAPP_SESSIONS_SECRET=...
```

---

## 📦 Dependencies

This tool uses the following open-source libraries (via CDN):

* [`js-yaml`](https://github.com/nodeca/js-yaml) – YAML parser
* [`crypto-js`](https://github.com/brix/crypto-js) – AES encryption library

---

## 🔐 Security Notes

* Store your encryption key securely. Do not hardcode it in production environments.
* Use the environment variable placeholder mode for safer deployments (especially with CI/CD).

---

## 🧑‍💻 License

MIT License © 2025 [Kamshory MT](https://github.com/planetbiru)

---

## 🌐 Live Demo

Not hosted online. Open `index.html` directly in your browser to use.

