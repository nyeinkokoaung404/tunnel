# 404Tunnel
# Cloudflare Workers and Pages generate node subscriptions

This is a script based on Cloudflare Workers and Pages platform. It modifies the original version to display VLESS configuration information and convert it into subscription content. With this script, you can easily convert VLESS and trojan configuration information to Clash, Singbox, Quantumult X and other tools using online configuration.

- TelegramChannel-1：[𝗙𝗢𝗥 𝗔𝗟𝗟 𝗢𝗙 𝗬𝗢𝗨](https://t.me/nkka_404)
- TelegramChannel-2：[ONLY/:FORYOU&ALL](https://t.me/Pmttg)
- VLESS Temporary subscription address：[VLESS](https://worker.amcloud.filegear-sg.me/866853eb-5293-4f09-bf00-e13eb237c655)

## Features

- **Text file storage**: You can store any text file in Cloudflare Workers KV key-value storage, including plain text, JSON, XML, and other formats.
- **Read files via URL**: You can read the contents of text files stored in KV by simply constructing a suitable URL.
- **Update files via URL**: You can use URL query parameters to upload new text content to KV to update files.
- **Base64 encoding support**: Supports uploading and downloading files using Base64 encoding to deal with some special character scenarios.
- **Secure access control**: By setting the token parameter, you can limit access to your files to only requests with the correct key.
- **Helper script**: Windows batch files and Linux Shell scripts are provided to easily upload files from local to KV.

- ## Instructions 

1. **Deploy to Cloudflare Workers**

Deploy the project code to your Cloudflare Workers service. You need to first create a Workers project on Cloudflare, then copy and paste the contents of the `_worker.js` file into the Workers editor.

2. **Create a KV namespace**

In the KV options in your Cloudflare Workers and Pages projects, create a new `KV` namespace to store text files. Note the name of this KV namespace because you need to bind it to Workers.

3. **Set a TOKEN variable**

- For added security, you need to set a TOKEN variable as a key to access the file. In the Cloudflare Workers environment variable settings, add a variable called `TOKEN` and give it a secure value.
- The default TOKEN is: `passwd`
- Find the "KV Namespace Binding" item in the variable, click Add Binding, add a variable named `KV`, and select a KV namespace. This is the name of the KV namespace created in step 2 above.

- 4. **Visit the configuration page**

For example, your workers project domain name is: `txt.anson.workers.dev`, token value is `passwd`;

- Visit `https://yourWorkers domain name/config?token=yourTOKEN` or `https://yourWorkers domain name/yourTOKEN`, you will see a configuration page with instructions and a link to download the script.

- Your project configuration page is:

```url
https://txt.anson.workers.dev/config?token=passwd
or
https://txt.anson.workers.dev/passwd
```

5. **Use auxiliary scripts to upload files**

- Windows users can download the `update.bat` script, and then execute `update.bat file name` to upload local files to KV.

- Linux users can download the `update.sh` script, and execute `./update.sh file name` to upload local files.
- **Note: Due to the URL length limit, if the saved content is too long, you can only modify and save the large file by directly editing the corresponding file content of `KV`. **

- 6. **Access files through URL**

For example, your workers project domain name is: `txt.anson.workers.dev`, token value is `test`, and the file name to be accessed is `ip.txt`;

- The format of constructing the URL is `https://yourWorkers domain name/file name?token=yourTOKEN`. You can view the contents of the file in the browser.
- Your access address is: `https://txt.anson.workers.dev/ip.txt?token=test`.

7. **Simple update of file content**

To update the contents of a file, you can use the URL query parameters `text` or `b64` to specify new text content or Base64-encoded content. The format of the URL is:

```url
https://yourWorkers domain name/file name?token=yourTOKEN&text=new text content
or
https://yourWorkers domain name/file name?token=yourTOKEN&b64=Base64-encoded new text content
```

Workers will automatically store the new content in the corresponding file.

With this serverless application, you can easily store and manage text files on Cloudflare's distributed network while enjoying the advantages of high performance and security and reliability. Welcome to CF-Workers-TEXT2KV!
