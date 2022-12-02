import pandas as pd
import aiohttp
import asyncio
import re
import cgi
import zipfile
import io
import json

import traceback
import logging

log = logging.getLogger(__name__)
import warnings
import requests

requests.packages.urllib3.disable_warnings()

from glob import glob
from pathlib import Path
from urllib.parse import urlparse
from urllib3.exceptions import NewConnectionError


def isin(chunk, *args):
    """checks if any of args are in the chunk"""
    return any([s in chunk for s in args])

# TODO these three arrays are currently unused
excel_suffixes = ['.xls', '.xlsx', '.xlsm']
text_suffixes  = ['.csv', '.txt', '.xml', '.json']
zip_suffixes   = ['.zip']

mrf_suffixes = excel_suffixes + text_suffixes + zip_suffixes


headers = {'Accept': '*/*',
           'Connection': 'keep-alive',
           'User-Agent': 'Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.1805 Safari/537.36',
           'Accept-Language': 'en-US;q=0.5,en;q=0.3',
           'DNT': '1',
           'Referer': 'https://google.com'}

def filename_check(filename: str) -> int:
    "Checks if filename meets requirements"
    rex = re.compile("[0-9]{2}-?[0-9]{7}_?.*_?standardcharges.*")
    if re.match(rex, filename):
        return 1
    return -1


def generic_code_check(chunk: str) -> int:
    "Checks if the chunk contains generic code info"
    if isin(chunk, "drg", "hcpcs", "cpt", "cmg"):
        return 1
    return -1


def gross_charges_check(chunk: str) -> int:
    "Checks if a chunk contains gross charge info" ""
    words = ["gross", "charge", "price", "rate", "pricing", "amount", "case rate"]
    if isin(chunk, *words):
        return 1
    return -1


def minmax_check(chunk: str) -> int:
    """Checks if a chunk contains information on minimum
    maximum negotiated charges"""
    words = [
        "minimum",
        "min neg ",
        "max neg",
        "minnegotiated",
        "de-identified",
        "maxofop",
        "maxop",
        "min_neg",
        "max_neg",
        "maxnegotiated",
        "min_negotiated",
        "max_negotiated",
    ]

    if isin(chunk, *words):
        return 1
    return -1


def cash_check(chunk: str) -> int:
    "Checks if a chunk contains information on cash prices"
    words = ["cash", "default cost", "self pay", "selfpay", "discounted"]
    if isin(chunk, *words):
        return 1
    return -1


def insurer_check(chunk: str) -> int:
    "Checks if a chunk contains insurer-specific information"
    words = [
        "anthem",
        "bcbs",
        "united",
        "ambetter",
        "aetna",
        "healthlink",
        "umr",
        "tricare",
        "uhc",
        "cigna",
        "kaiser",
        "permanente",
        "molina",
        "centene",
        "blue cross",
        "blue shield",
        "caresource",
        "upmc",
        "carefirst",
        "cvs health",
    ]

    if isin(chunk, *words):
        return 1
    return -1


def score_chunk(url: str, chunk: str) -> tuple:
    """Given a URL, check compliance on a bunch of dimensions
    and give it a final tally (total)"""

    filename = urlparse(url).path.split("/")[-1].lower()
    filename_score = filename_check(filename)

    chunk = str(chunk).lower()

    gross_score = gross_charges_check(chunk)
    minmax_score = minmax_check(chunk)
    cash_score = cash_check(chunk)
    generic_score = generic_code_check(chunk)
    insurer_score = insurer_check(chunk)

    scores = (
        gross_score,
        minmax_score,
        cash_score,
        generic_score,
        insurer_score,
        filename_score,
    )

    total = sum([s for s in scores if s == 1])

    return *scores, total


def check_url(url, chunk):
    """
    Checks compliance on a chunk of bytes
    from a URL
    """
    chunk = str(chunk).lower()
    filename = urlparse(url).path.split("/")[-1].lower()

    gross_chk = gross_charges_check(chunk)
    minmax_chk = minmax_check(chunk)
    cash_chk = cash_check(chunk)
    generic_chk = generic_code_check(chunk)
    insurer_chk = insurer_check(chunk)
    filename_chk = filename_check(filename)

    return gross_chk, minmax_chk, cash_chk, generic_chk, insurer_chk, filename_chk


def excel_to_chunk(data: bytes, chunk_len: int) -> str:
    """Return a string with n_bytes from
    each sheet in the .xlsx file. Basically just converts
    the dataframe to JSON and reads the first n_bytes of that.
    Total hack.

    sheet_name = None makes sure that we return all sheets
    """
    warnings.simplefilter(action="ignore", category=UserWarning)

    chunk = ""
    df = pd.read_excel(data, sheet_name=None)

    for key in df.keys():
        chunk += str(df[key].to_csv())[:chunk_len]

    return chunk


def json_to_chunk(data: bytes, chunk_len: int) -> str:
    "Hackjob for reading in 'header' information from JSON"
    if type(data) == list:
        data = data[0]

    keys = data.keys()

    chunk = "".join([k.lower() for k in keys])
    chunk += str(data).lower()[:chunk_len]

    return chunk


def zip_to_chunk(data: bytes, chunk_len: int) -> str:
    "Hackjob for reading in zip files"
    z = zipfile.ZipFile(io.BytesIO(data))

    log.debug("Opened zip file")

    chunk = ""
    for file in z.namelist():
        with z.open(file) as f:

            suffix = Path(file).suffix.lower()

            if suffix == ".json":
                data = json.load(f)
                _chunk = json_to_chunk(data, chunk_len)

            elif suffix in (".csv", ".xml", ".txt"):
                _chunk = str(f.read(chunk_len))

            elif suffix in (".xlsx", ".xls", ".xlsm", ".xlsb"):
                _chunk = excel_to_chunk(f, chunk_len)

            else:
                # Haven't implemented this yet
                continue
            chunk += _chunk

    return chunk


async def get_cookies_and_filename(
    session: aiohttp.ClientSession, url: str, headers: dict
) -> tuple:
    """
    In one request, fetch cookies needed to make second request
    and filename needed to figure out how to process the chunk
    we get.
    """

    filename = Path(url)
    cookies = None

    async with session.head(url, ssl=False, headers=headers) as r:

        cookies = r.cookies
        header_data = r.headers.get("Content-Disposition")

        if header_data:
            _, params = cgi.parse_header(header_data)
            if params.get("filename"):
                filename = params.get("filename")

    return cookies, filename


async def get_chunk(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
    cookies: dict,
    suffix: str,
    chunk_len: int,
) -> str:
    """Get the first chunk of data from a url"""

    if suffix not in mrf_suffixes:
        raise NotImplementedError

    async with session.get(url, ssl=False, headers=headers, cookies=cookies) as r:

        if suffix in (".csv", ".txt", ".xml"):
            async for _chunk in r.content.iter_chunked(chunk_len):
                chunk = _chunk
                break

        elif suffix in (".xlsx", ".xls", ".xlsb", ".xlsm"):
            data = await r.read()
            chunk = excel_to_chunk(data, chunk_len)

        elif suffix == ".json":
            data = await r.json()
            chunk = json_to_chunk(data, chunk_len)

        elif suffix == ".zip":
            data = await r.read()
            chunk = zip_to_chunk(data, chunk_len)

        return chunk

async def checker(session: aiohttp.ClientSession, url: str) -> tuple:
    """
    Returns scores, an array
    The parameters are:
    -1: noncompliant
     0: unknown
     1: compliant

    "err" is either
    0: no error
    1: no url or invalid URL
    2: server error
    3: 404
    4: got a url, but didn't know what to do with it
    5: something else
    """

    err = None
    scores = [0] * 7
    cookies = None
    filename = url
    chunk = None

    # log.debug(url)

    if not url:
        err = 1
        return *scores, err

    if (
        ("cdmpricing.com" in url)
        or ("hospitalpriceindex.com" in url and "machineReadable" in url)
        or ("claraprice.net" in url)
    ):
        """
        Special cases: these URLs host
        only compliant chargemasters.
        """
        scores = (1, 1, 1, 1, 1, 1, 6)
        err = 0
        return *scores, err

    if "allowed-amounts.json" in url or ("_index.json") in url:
        """
        These are known to be mistakes.
        """
        err = 1
        return *scores, err

    try:
        cookies, filename = await get_cookies_and_filename(session, url, headers)
    except Exception as e:
        # log.exception(e)
        ...

    suffix = Path(filename).suffix.lower()

    try:
        chunk = await get_chunk(session, url, headers, cookies, suffix, chunk_len=5_000)

    except aiohttp.InvalidURL:
        err = 1

    except (
        aiohttp.ClientPayloadError,
        aiohttp.ClientConnectorError,
        aiohttp.ClientConnectionError,
        aiohttp.ServerDisconnectedError,
        NewConnectionError,
        asyncio.TimeoutError,
        asyncio.CancelledError,
        TimeoutError,
        ValueError,
    ):
        err = 2

    except aiohttp.ClientResponseError as e:
        err = 3

    except NotImplementedError:
        err = 4

    else:
        err = 5

    finally:

        if chunk:
            err = 0
            scores = score_chunk(url, chunk)

        # if scores[-1] == 0 and err == 0:
        # log.debug(f'A score of zero was found for the following file: {url}')
        # log.debug(f'The file had suffix {suffix} and the chunk has length: {len(chunk)}')
        # log.debug('This is the chunk that was returned:')
        # log.debug('---'*10)
        # log.debug(chunk)
        # log.debug('---'*10)

        if err == None:
            log.debug(url)
            raise

        return *scores, err
