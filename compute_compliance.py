from typing import List

import aiohttp
import asyncio
import re
import cgi
import zipfile
import io
import json
import pandas as pd

import requests
requests.packages.urllib3.disable_warnings() 

from pathlib import Path
from urllib.parse import urlparse

from pandas.core.frame import validate_axis_style_args
from tqdm.asyncio import tqdm


import polars as pl

def isin(chunk, *args):
    '''checks if any of args are in the chunk'''
    return any([s in chunk for s in args])

def filename_check(filename):
    rex = re.compile('[0-9]{2}-?[0-9]{7}_?.*_?standardcharges.*')
    if re.match(rex, filename):
        return 1
    return -1

def gross_charges_check(chunk):
    if isin(chunk, 'gross', 'charge', 'price', 'rate'):
        return 1
    return -1

def minmax_check(chunk):
    chk_words = [
        'minimum', 'min neg ', 'max neg', 'minnegotiated',
        'de-identified',
        'maxofop', 'maxop',
        'min_neg', 'max_neg',
        'maxnegotiated', 'min_negotiated',
        'max_negotiated'
    ]
    if isin(chunk, *chk_words):
        return 1
    return -1

def cash_check(chunk):
    if isin(chunk, 'cash', 'default cost', 'self pay', 'selfpay'):
        return 1
    return -1

def insurer_check(chunk):
    if isin(chunk, 'anthem', 'bcbs', 'united', 'ambetter', 'aetna',
            'healthlink', 'umr', 'tricare', 
            'uhc', 'cigna', 'kaiser', 'permanente', 'molina', 
            'centene', 'blue cross', 'blue shield', 'caresource', 
            'upmc', 'carefirst', 'cvs health',
            ):
        return 1
    return -1

def generic_code_check(chunk):
    if isin(chunk, 'drg', 'hcpcs', 'cpt', 'cmg'):
        return 1
    return -1

def check_url(url, chunk):
    '''
    Checks compliance on a chunk of bytes
    from a URL
    '''
    chunk = str(chunk).lower()
    filename = urlparse(url).path.split('/')[-1].lower()
    
    gross_chk = gross_charges_check(chunk)
    minmax_chk = minmax_check(chunk)
    cash_chk = cash_check(chunk)
    generic_chk = generic_code_check(chunk)
    insurer_chk = insurer_check(chunk)
    filename_chk = filename_check(filename)
    
    return gross_chk, minmax_chk, cash_chk, generic_chk, insurer_chk, filename_chk


def excel_decoder(data, n_bytes):
    '''
    Return a string with n_bytes from 
    each sheet in the .xlsx file. Basically just converts
    the dataframe to JSON and reads the first n_bytes of that.
    Total hack.

    sheet_name = None makes sure that we return all sheets
    '''
    
    n_chars = n_bytes * 8
    chunk = ''
    df = pd.read_excel(data, sheet_name = None)
    for key in df.keys():
        chunk += str(df[key].to_csv())[:n_chars]
    return chunk

def json_decoder(data, n_bytes):
    '''
    Hackjob for reading in "header" information
    from JSON
    '''
    n_chars = n_bytes * 8

    if type(data) == list:
        data = data[0]

    keys = data.keys()

    chunk = ''.join([k.lower() for k in keys])
    chunk += str(data).lower()[:n_chars]
    return chunk

def zip_decoder(data, n_bytes):
    '''
    Hackjob for reading in zip files
    '''
    n_chars = n_bytes * 8
    z = zipfile.ZipFile(io.BytesIO(data))
    files = z.namelist()
    for file in files:
        with z.open(file) as f:
            suffix = Path(file).suffix.lower()
            if suffix == '.json':
                data = json.load(f)
                chunk = json_decoder(data, 1_000)
                return chunk
            elif suffix in ('.csv', '.xml', '.txt'):
                chunk = f.read(1_000)
                return chunk
            else:
                raise Exception("Not supported")
            
headers = {'Accept': '*/*',
 'Connection': 'keep-alive',
 'User-Agent': 'Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.1805 Safari/537.36',
 'Accept-Language': 'en-US;q=0.5,en;q=0.3',
 'DNT': '1',
 'Referer': 'https://google.com'}


async def checker(session, url):
    '''
    Returns vals, an array
    the first six parameters are either -1, 0, or 1
    -1: noncompliant
     0: unknown
     1: compliant

    The last parameter of vals is either 0, 1, 2, or 3
    0: no error
    1: no url
    2: unknown error
    3: 404
    '''
    
    vals = [0]*7
    
    if not url:
        vals[-1] = 1
        return vals

    try:
        cookies = requests.get(url, verify = False, headers = headers, stream = True).cookies

        async with session.get(url, 
                               ssl = False, 
                               headers = headers, 
                               cookies = cookies) as r:
            
            # update filename if fetches remote file
            header = r.headers.get('Content-Disposition')
            if header:
                _, params = cgi.parse_header(header)
                if params.get('filename'):
                    url = params.get('filename')
                    
            suffix = Path(url).suffix.lower()

            if ('cdmpricing.com' in url
                or ('hospitalpriceindex.com' in url and 'machineReadable' in url)
                or ('claraprice.net' in url)
                ):
                '''
                Special cases: these URLs host
                only compliant chargemasters.
                '''
                vals = [1, 1, 1, 1, 1, 1, 0]
                return vals
            
            if suffix in ('.csv', '.txt', 'xml'):
                async for chunk in r.content.iter_chunked(4_000):
                    vals = *check_url(url, chunk), 0
                    return vals
                    
            elif suffix == '.xlsx':
                data = await r.read()
                chunk = excel_decoder(data, 1_000)
                vals = *check_url(url, chunk), 0
                return vals
            
            elif suffix == '.json':
                data = await r.json()
                chunk = json_decoder(data, 1_000)
                vals = *check_url(url, chunk), 0
                return vals

            elif suffix == '.zip':
                data = await r.read()                
                chunk = zip_decoder(data, 1_0000)
                return vals

            elif suffix == '.pdf':
                return vals
            
            else:
                return vals

    except aiohttp.ClientResponseError:
        vals[-1] = 3
        return vals

    except (aiohttp.ClientPayloadError,
            aiohttp.ClientConnectorError,
            aiohttp.ServerDisconnectedError,
            aiohttp.InvalidURL,
            TimeoutError,
            ValueError):
        vals[-1] = 2
        return vals

    except Exception as e:
        raise
        if e == 'Not supported':
            vals[-1] = 2
            return vals
        vals[-1] = 2
        return vals
    

async def check(df):
    async with aiohttp.ClientSession(raise_for_status = True) as session:
        t = df.sample(1000)
        cols = ['gross_chk', 'minmax_chk', 'cash_chk', 'generic_chk', 'insurer_chk', 'filename_chk', 'err']
        t[cols] = await tqdm.gather(*(checker(session, url) for url in t['cdm_url']))

        # Add up all the values (except the error col) where the col equals 1
        t = t.with_column(
            pl.fold(pl.lit(0), lambda score, v: score + v.is_in([1]), cols[:-1]).alias('score')
        )

        t = t.sort('score')

        return t