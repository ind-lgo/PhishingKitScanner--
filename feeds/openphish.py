'''Implements a provider for the OpenPhish free phishing feed.'''
import hashlib

from feeds.feed import Feed
from models import Phish

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By

class OpenphishFeed(Feed):
    '''Implements a provider for the OpenPhish free phishing feed.'''

    def __init__(self):
        '''Creates a new instance of the OpenPhish feed.'''
        self.feed = 'openphish'
        self.url = "https://openphish.com/index.html"

    def _process_urls(self, urls):
        '''
        Processes new phishing entries from the OpenPhish feed.
        Every line is simply a URL for a phishing site. We need to
        check for existence and create the `models.Phish` entry to use for storage.
        For the OpenPhish feed, the PID is simply the hash of the URL.
        Args:
            urls {list[str]} - The urls to process
        '''
        entries = []
        urls_seen = []
        for url in urls:
            if Phish.clean_url(url) in urls:
                continue
            url_hash = hashlib.sha1()
            url_hash.update(url.encode('utf-8'))
            urls_seen.append(Phish.clean_url(url))
            entries.append(
                Phish(pid=url_hash.hexdigest(), url=url, feed=self.feed))
        return entries
        
    

    def get(self):
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
        driver.get(self.url)
        urls = driver.find_elements(By.XPATH, '//td[@class = "url_entry"]')
        
        urls_seen = []
        for url in urls:
            urls_seen.append(url.text)
            
        return self._process_urls(urls_seen)
