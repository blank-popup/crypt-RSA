# RSA
## Usage
```
cryptc.exe generate_key_pair 2048 private.pem public.pem
cryptc.exe encrypt_public 2048 public.pem plain
cryptc.exe decrypt_private 2048 private.pem crypt
cryptc.exe encrypt_private 2048 private.pem plain
cryptc.exe decrypt_public 2048 public.pem crypt
```

## Example
```
d:\WorkSpace\crypt\x64\Debug>cryptc.exe generate_key_pair 2048 private.pem public.pem
Parameter[1]: [generate_key_pair]
Parameter[2]: [2048]
Parameter[3]: [private.pem]
Parameter[4]: [public.pem]

d:\WorkSpace\crypt\x64\Debug>cryptc.exe encrypt_public 2048 public.pem plainPhrase123!@#$
Parameter[1]: [encrypt_public]
Parameter[2]: [2048]
Parameter[3]: [public.pem]
Parameter[4]: [plainPhrase123!@#$]
Output: [s0Z9PiEB+oJ7XH7RviccJWyQsNynkrNR0/hd8vRvZNVJglrZSeWc5tZh6xd/L+JfrT+Yt5JAxq+jSi9yl+VCacqOiS3qOfCpufEWY5Dq2hLU/PyZbHE/Mtx8g7VmM731LBEYA3h7X3ec13qJEdJc8ceTTnHwjgmhnjEOULvlYYC4QOeO9HWN5Sq+//KZyQW+J/mNdcnzJTCrApNAYjeg6hs1o68vkllB0ABIxSv3pmcAK8sPWtYC5Dwr4IeYZUCVsTzMah5VidDZGk7UXCt3MooVtZG9A2bwiQxBmqrehX9Ep8epIz4hIg5gBfVviY0DcyfssvyEJy+/W6K6r1R1XQ==], [344]

d:\WorkSpace\crypt\x64\Debug>cryptc.exe decrypt_private 2048 private.pem s0Z9PiEB+oJ7XH7RviccJWyQsNynkrNR0/hd8vRvZNVJglrZSeWc5tZh6xd/L+JfrT+Yt5JAxq+jSi9yl+VCacqOiS3qOfCpufEWY5Dq2hLU/PyZbHE/Mtx8g7VmM731LBEYA3h7X3ec13qJEdJc8ceTTnHwjgmhnjEOULvlYYC4QOeO9HWN5Sq+//KZyQW+J/mNdcnzJTCrApNAYjeg6hs1o68vkllB0ABIxSv3pmcAK8sPWtYC5Dwr4IeYZUCVsTzMah5VidDZGk7UXCt3MooVtZG9A2bwiQxBmqrehX9Ep8epIz4hIg5gBfVviY0DcyfssvyEJy+/W6K6r1R1XQ==
Parameter[1]: [decrypt_private]
Parameter[2]: [2048]
Parameter[3]: [private.pem]
Parameter[4]: [s0Z9PiEB+oJ7XH7RviccJWyQsNynkrNR0/hd8vRvZNVJglrZSeWc5tZh6xd/L+JfrT+Yt5JAxq+jSi9yl+VCacqOiS3qOfCpufEWY5Dq2hLU/PyZbHE/Mtx8g7VmM731LBEYA3h7X3ec13qJEdJc8ceTTnHwjgmhnjEOULvlYYC4QOeO9HWN5Sq+//KZyQW+J/mNdcnzJTCrApNAYjeg6hs1o68vkllB0ABIxSv3pmcAK8sPWtYC5Dwr4IeYZUCVsTzMah5VidDZGk7UXCt3MooVtZG9A2bwiQxBmqrehX9Ep8epIz4hIg5gBfVviY0DcyfssvyEJy+/W6K6r1R1XQ==]
Output: [plainPhrase123!@#$], [18]

d:\WorkSpace\crypt\x64\Debug>cryptc.exe encrypt_private 2048 private.pem 123!@#$plainPhrase
Parameter[1]: [encrypt_private]
Parameter[2]: [2048]
Parameter[3]: [private.pem]
Parameter[4]: [123!@#$plainPhrase]
Output: [YVUhZAyiZ2a2CXiYIsFHu+g5yjhOrYaxI0YWTUyKJEG/EV0l+RpXZDtiN2ONiqllVMAKnewG1TyCabftLJeK5Q4XQH/kztrnKrbZTEIPIg8ANr6VPISl4PbC6LAD9tNxlTNg68u4lP6kIGriXDCTMZqBd8cBKd6dt+VN5goT3vSYiquMDUmks1ikduoA0tyfCVmtFky72EPlmAX1mVZO9EWjc5uQYtKWiVvP1hYedAyibNR1ce3k7Jcpq/Lb1AS/R4ILMu0Jc5DjIvW2qGXpfGEk4Q65SmHv9jdrbWAwA3Z93tL+aCxj2th43E5KQVgHJC0ZW1jxDxlnlk7IB28rAg==], [344]

d:\WorkSpace\crypt\x64\Debug>cryptc.exe decrypt_public 2048 public.pem YVUhZAyiZ2a2CXiYIsFHu+g5yjhOrYaxI0YWTUyKJEG/EV0l+RpXZDtiN2ONiqllVMAKnewG1TyCabftLJeK5Q4XQH/kztrnKrbZTEIPIg8ANr6VPISl4PbC6LAD9tNxlTNg68u4lP6kIGriXDCTMZqBd8cBKd6dt+VN5goT3vSYiquMDUmks1ikduoA0tyfCVmtFky72EPlmAX1mVZO9EWjc5uQYtKWiVvP1hYedAyibNR1ce3k7Jcpq/Lb1AS/R4ILMu0Jc5DjIvW2qGXpfGEk4Q65SmHv9jdrbWAwA3Z93tL+aCxj2th43E5KQVgHJC0ZW1jxDxlnlk7IB28rAg==
Parameter[1]: [decrypt_public]
Parameter[2]: [2048]
Parameter[3]: [public.pem]
Parameter[4]: [YVUhZAyiZ2a2CXiYIsFHu+g5yjhOrYaxI0YWTUyKJEG/EV0l+RpXZDtiN2ONiqllVMAKnewG1TyCabftLJeK5Q4XQH/kztrnKrbZTEIPIg8ANr6VPISl4PbC6LAD9tNxlTNg68u4lP6kIGriXDCTMZqBd8cBKd6dt+VN5goT3vSYiquMDUmks1ikduoA0tyfCVmtFky72EPlmAX1mVZO9EWjc5uQYtKWiVvP1hYedAyibNR1ce3k7Jcpq/Lb1AS/R4ILMu0Jc5DjIvW2qGXpfGEk4Q65SmHv9jdrbWAwA3Z93tL+aCxj2th43E5KQVgHJC0ZW1jxDxlnlk7IB28rAg==]
Output: [123!@#$plainPhrase], [18]

d:\WorkSpace\crypt\x64\Debug>
```

## Environment
Windows 11  
Visual Studio 2022  
Win64 OpenSSL v3.0.7 (http://slproweb.com/products/Win32OpenSSL.html)
