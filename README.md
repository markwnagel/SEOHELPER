# as prompted

A password-protected single page. `index.html` contains only encrypted content and an unlock form; the browser decrypts it (PBKDF2 + AES-GCM via the Web Crypto API) when the right password is entered. The password is not stored in this repository.

## Updating the page

The readable source is kept outside this repository. After editing it, re-encrypt and commit the result:

```bash
SITE_PASSWORD='your-password' node encrypt.js path/to/source.html index.html
```

## Hosting

GitHub Pages: Settings → Pages → deploy from the `main` branch, root folder.
