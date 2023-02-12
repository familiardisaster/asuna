from re import findall
from urllib.parse import urlparse, parse_qsl
#----------------------------------------------------------------------------------------------------------------------------------#
def txt_to_set(path, iterable):
    with open(path, 'r') as txt:
        if type(iterable) == list:
            iterable.extend([str(row).rstrip('\n') for row in txt if row])
        elif type(iterable) == set:
            iterable.update([str(row).rstrip('\n') for row in txt if row])
        else:
            print('You tried to txt_to_iterable something that is neither a list nor a set.')
#----------------------------------------------------------------------------------------------------------------------------------#
def iterable_to_txt(path, iterable, append=False):
    with open(path, 'w' if not append else 'a+') as txt:
        txt.writelines([str(item) + '\n' for item in iterable])
#----------------------------------------------------------------------------------------------------------------------------------#
def urlor(path):
    URL_REGEX = r'''(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-&?=%.]+'''
    with open(path, 'r') as file:
        urls = findall(URL_REGEX,  file.read())
    return urls
#----------------------------------------------------------------------------------------------------------------------------------#
def pathor(path):
    urls = urlor(path)
    return [urlparse(url).path for url in urls if '/' in url and not url.startswith('/')]
#----------------------------------------------------------------------------------------------------------------------------------#
def subor(path):
    with open(path) as txt:
        return [urlparse(line).hostname for line in txt]
#----------------------------------------------------------------------------------------------------------------------------------#
def paramor(path):
    urls = urlor(path)
    return [parse_qsl(urlparse(url).query) for url in urls if urlparse(url).query]
#----------------------------------------------------------------------------------------------------------------------------------#
def nuclei_parser(infile,outfile):
    regex = r'\[([^]]*)\]'
    with open(infile.encode('unicode-escape').decode(), 'r') as infile, open(outfile.encode('unicode-escape').decode(), 'w') as outfile:
        for line in infile:
            matches = findall(regex, line)
            outfile.writelines(match + '\n' for match in matches)
#----------------------------------------------------------------------------------------------------------------------------------#