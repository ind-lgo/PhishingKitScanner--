''' Creates the models for the phish collector '''
from datetime import datetime
from elasticsearch import Elasticsearch
from urllib.parse import urlparse

class Phish(object):
    ''' A class representing a possible phishing site '''
    _index = 'samples'
    _type = 'phish'

    def __init__(self, *args, **kwargs):
        self.pid = kwargs.get('pid')
        self.url = kwargs.get('url')
        self.index_url = Phish.clean_url(self.url)
        self.ip_address = kwargs.get('ip_address', '0.0.0.0')
        self.feed = kwargs.get('feed')
        self.indexing_enabled = kwargs.get('indexing_enabled', False)
        self.has_kit = kwargs.get('has_kit', False)
        self.kits = kwargs.get('kits', [])
        self.timestamp = datetime.now()
        self.status_code = kwargs.get('status_code')
        self.html = kwargs.get('html')

    @classmethod
    def clean_url(cls, url):
        ''' Cleans the URL provided to be a basic scheme://host/path format.

        This removes any params, trailing slashes, etc. to help us remove duplicate
        URLs from our index.

        Args:
            url {str} - The URL to search
        '''
        parts = urlparse(url)
        path = parts.path
        # Strip the trailing slash
        if path and path[-1] == '/':
            path = path[:-1]
        clean_url = '{}://{}{}'.format(parts.scheme, parts.netloc.encode('utf-8'), path.encode('utf-8', 'ignore'))
        return clean_url


class PhishKit(object):
    ''' A class representing phishing kits stored on the filesystem.

    Phishkits are stored as child objects in a one-to-many relationship with Phish samples.'''
    _index = 'samples'
    _type = 'kit'

    def __init__(self, **kwargs):
        '''
        Creates a new instance of the phishkit metadata entry to be stored
        in Elasticsearch
        '''
        self.hash = kwargs.get('hash')
        self.filepath = kwargs.get('filepath')
        self.filename = kwargs.get('filename')
        self.url = kwargs.get('url')
        self.emails = kwargs.get('emails')
        self.parent = kwargs.get('parent')
