import hashlib
import logging
from charset_normalizer import detect
import requests
import socket
import os
from zipfile import ZipFile, is_zipfile

from datetime import datetime
from urllib.parse import urlparse
from queue import Queue
from multiprocessing import Pool
import urllib3
from feeds import feeds
from models import Phish


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='main.log')

BLACKLIST = []
KIT_DIR = 'kits'
MAX_LINES_PER_DIR = 100


class Collector(object):
    ''' A class that handles collecting phishing sites '''

    def __init__(self):
        ''' Creates a new instance of the collector'''
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent':
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36'
        })
        self.config = {
            "kit_directory": KIT_DIR,
            "max_links_per_directory" : MAX_LINES_PER_DIR}

    def collect(self, sample):
        ''' Collects the data associated with a phishkit '''
        try:
            parts = urlparse(sample.url)
            print(parts)
            if parts.netloc in BLACKLIST:
                raise Exception('Sample URL is blacklisted from analysis.')

            # Some URLs are in the form hxxp://example.com
            if 'hxx' in parts.scheme:
                sample.url = sample.url.replace('hxxp', 'http', 1)

            status_code, html = self.collect_html(sample.url)
            sample.html = html
            sample.status_code = status_code
            sample.ip_address = self.lookup_ip(sample.url)

            kits = self.collect_kits(sample)

            # Index the sample and the found kits
            sample.timestamp = datetime.now()
            for kit in kits:
                sample.kits.append(kit.hash)
        except Exception as e:
            # Give a reasonable error status
            sample.status_code = 0
            sample.html = ''
            sample.timestamp = datetime.now()
            
            
    def lookup_ip(self, url):
        '''
        Returns the IP address the URL resolves to. 
        TODO: We'll want to remove the port if it exists.
        Args:
            url - The URL of the phishing page
        '''
        try:
            parts = urlparse(url)
            return socket.gethostbyname(parts.netloc)

        except Exception:
            return None
    
    
    def download_kit(self, url, pid):
        '''
        Attempts to fetch a file at the current URL
        Args:
            url {str} - The URL to attempt to fetch the kit for
            pid {str} - The phishing url ID
        '''
        kit = None
        try:
            response = self.session.get(
                url, stream=True, verify=False, timeout=5)
            if not response.ok:
                logging.info('Invalid response for zip URL: {} : {}'.format(
                    url, str(response.status_code)))
                return kit
            if 'text/html' in response.headers.get('Content-Type'):
                return kit
            filename = url.split('/')[-1]
            filepath = '{}/{}-{}'.format(self.config['kit_directory'], pid,
                                         filename)
            filesize = 0

            
            kit_hash = hashlib.sha1()
            with open(filepath, 'wb') as kit_file:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        kit_hash.update(chunk)
                        kit_file.write(chunk)
                        filesize += len(chunk)
            logging.info('Found kit for {}'.format(url))
        except Exception as e:
            logging.info('error for {} : {}'.format(url, e))

    def collect_kits(self, sample):
        '''
        Crawls the site looking for open directories or zip files
        left available to the public
        '''
        queue = Queue()
        parts = urlparse(sample.url)
        paths = parts.path.split('/')[1:]
        kits = []
        kit_urls = []
        crawled = []

        # Add the initial paths to our queue
        for i in range(1, len(paths)):
            phish_url = '{}://{}/{}/'.format(parts.scheme, parts.netloc,
                                             '/'.join(paths[:len(paths) - i]))
            queue.put(phish_url)
            crawled.append(phish_url)

        # Try to get the ZIP by looking for open directories - if we find other sub-
        # directories in an open index, add those to the queue.
        while not queue.empty():
            phish_url = queue.get()
            logging.info(
                'Checking for open directory at: {}'.format(phish_url))

            links = None
            if not links:
                continue
            # Wordt dit wel uitgevoerd???
            print("AAAAAAA, Wordt dit wel uitgevoerd?")
            sample.indexing_enabled = True
            directory_links = 0
            for link in links:
                if link in crawled:
                    continue
                if link.endswith('.zip'):
                    kit = self.download_kit(link, sample.pid)
                    if kit:
                        sample.has_kit = True
                        kits.append(kit)
                        kit_urls.append(link)
                    continue
                if link[-1] == '/':
                    # Short circuit if this directory is huge - won't stop us from finding
                    # a kit if it's in the same directory
                    directory_links += 1
                    if directory_links > self.config['max_links_per_directory']:
                        continue
                    logging.info('Adding URL to Queue: {}'.format(link))
                    queue.put(link)
                    crawled.append(link)

        for phish_url in crawled:
            # Remove the trailing slash and add .zip
            phish_url = '{}.zip'.format(phish_url[:-1])
            if phish_url in kit_urls:
                logging.info(
                    'Skipping URL since the kit was already downloaded: {}'.
                    format(phish_url))
                continue
            logging.info('Fetching kit by zip {}'.format(phish_url))

            kit = self.download_kit(phish_url, sample.pid)
            if kit:
                sample.has_kit = True
                kits.append(kit)
        return kits
    
    
    def collect_html(self, url):
        '''
        Fetches the HTML of a phishing page
        Args:
            url {str} - The URL to fetch
        
        Returns:
            status_code {int} The status code of the HTTP response
            html {str} The HTML returned
        '''

        logging.info('Fetching {}'.format(url))
        try:
            response = self.session.get(url, verify=False, timeout=3)
            if not response.ok:
                logging.debug('Unsuccessful response for sample: {} : {}'.
                              format(url, response.text))
            return response.status_code, response.text
        except Exception:
            logging.info('Invalid response for sample: {}'.format(url))
            return 0, ''


def process_sample(sample):
    c = Collector()
    try:
        c.collect(sample)
    except Exception as e:
        logging.info('Error processing sample: {}: {}'.format(
            sample.url.encode('utf-8'), e))


def detect_files():
    keywords = []
    with open("detection.txt", "r") as f:
        for line in f.readlines():
            keywords.append(line.strip("\n").encode('utf-8'))
    
    detected_files = []  
    for filename in os.listdir(KIT_DIR): 
        path = os.path.join(KIT_DIR, filename)
        if is_zipfile(path):
            with ZipFile(path, 'r') as zip:
                listOfiles = zip.namelist()
                for file in listOfiles:
                    txtdata = zip.read(file)
                    if any(word in txtdata for word in keywords):
                        detected_files.append(filename + ";" + file + "\n")
                        logging.info('{} contains keyword'.format(file))
        else:
            print(path, "NOT A ZIP/PHP")
    return detected_files


def main():
    logging.info('---------------------------------------')
    logging.info('Report for timestamp: {}'.format(datetime.now()))
    logging.info('---------------------------------------')
    pool = Pool(8)
    samples = []
    urls = []
    
    for feed in feeds:
        results = feed.get()
        for result in results:
            print(result.index_url)
        # We need to make sure a URL isn't appearing in both feeds at the same time
        for sample in results:
            clean_url = Phish.clean_url(sample.url)
            if clean_url in urls:
                logging.info('URL {} appears in both feeds.'.format(clean_url))
                continue
            urls.append(clean_url)
            samples.append(sample)

        if results:
            logging.info("Found {} {} samples with final pid: {}".format(
                len(samples), feed.feed, results[-1].pid))
        else:
            logging.info("No samples found for {}".format(feed.feed))
    
    pool.map(process_sample, samples)
    pool.close()
    pool.join()
    
    detected_files = detect_files()
    with open("detected_files.txt", "w") as f:
        """Writes the zip/php filename and the specific file 
        that contains the keywords to 'detected_files.txt'"""
        for file in detected_files:
            f.write(file)
            

if __name__ == '__main__':
    main()
