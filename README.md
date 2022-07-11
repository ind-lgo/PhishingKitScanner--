

# Phising kit scanner 
* Basic Phising kit scanner *

**Phising kit scanner ** is a tool created for scannig openphish.com  URL. the tool  is designed to try finding phishing kits sources and webshells .
Some scammers can't or don't remove their phishing kit sources when they deploy it.
You can try to find these sources to extract some useful information as: e-mail addresses where the  stolen data is being sent 
some more information about scammer or phishing kit developer. From there you can extend your knowledge about the threat and organizations,
and get much useful information for your investigations.

## Features
- find zip file of the phishing kit 
- find and detected webshells 
- find if the phishing kit is still up and running
- download html and webshell files 
- try to download phishing kit sources (trying to find .zip file)

## Requirements
* Python 3
* BeautifulSoup4
* selenium 
* requests



## Install
Install the requirements
~~~
pip3 install -r requirements.txt 

python main.py 
~~~


