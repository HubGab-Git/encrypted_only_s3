command to send encrypted file to s3:

```md
aws s3 cp main.tf s3://encrypted-only-hubix/main.tf --sse AES256
```