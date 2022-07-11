import hashlib
from charset_normalizer import detect
import requests
import logging
import os
from datetime import datetime
from models import  PhishKit
from feeds import OpenphishFeed

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='main.log')

KIT_DIRECTORY = "kits"
MAX_LINKS_PER_DIRECTORY = 100


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
            "kit_directory": KIT_DIRECTORY,
            "max_links_per_directory" : MAX_LINKS_PER_DIRECTORY}


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
            
            filename = url.split('/')[-1]
            filepath = '{}/{}'.format(self.config['kit_directory'], pid) + filename
            
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


def process_sample(sample):
    c = Collector()
    try:
        c.download_kit(sample)
    except Exception as e:
        logging.info('Error processing sample: {}: {}'.format(
            sample.url.encode('utf-8'), e))


def detect_files():
    keywords = []
    with open("detection.txt", "r") as f:
        for line in f.readlines():
            keywords.append(line.strip("\n"))
    
    detected_files = []  
    for filename in os.listdir(KIT_DIRECTORY):      
        path = os.path.join(KIT_DIRECTORY, filename)
        if os.path.isfile(path):
            with open(path, "r") as f:
                try:
                    page = f.read()
                    if any(word in page for word in keywords):
                        detected_files.append(filename + "\n")
                        logging.info('{} contains keyword'.format(filename) + keywords[page])
                except UnicodeDecodeError as e:
                    logging.info('error for {} : {}'.format(f, e))
    return detected_files


def main():    
    logging.info('---------------------------------------')
    logging.info('Report for timestamp: {}'.format(datetime.now()))
    logging.info('---------------------------------------')
    
    c = Collector()
    
    """Retrieve Phish's from OpenPhish"""
    phish_objs = OpenphishFeed().get()
    
    """Check urls and download kit(s)"""
    for phish in phish_objs:
        c.download_kit(phish.url, phish.pid)
        print(phish.url)
    
    """Write names of files that contain keyword to txt"""
    detected_files = detect_files()
    with open("detected_files.txt", "w") as f:
        for file in detected_files:
            f.write(file)
            

if __name__ == '__main__':
    main()
