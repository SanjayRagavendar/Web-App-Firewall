import pandas as pd
import urllib
import os
import re
import urllib
import string
from nltk.tokenize import RegexpTokenizer
from nltk.stem import SnowballStemmer
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE
import joblib


    return l
result = []
for d in l:
    d = str(urllib.parse.unquote(d))
    result.append(d)


df = pd.DataFrame(result)
df.columns = ["query"]
def clean_newline(column):
    column[:-2]
    return column[:-2]

df["query"] = df["query"].apply(clean_newline)

def clear_first_char(column):
    if column.startswith("/"):
        return column[1:]
    else:
        return column

df["query"] = df["query"].apply(clear_first_char)

def xss_check(input_string):
    input_string = urllib.parse.unquote(input_string)
    xss_pattern=re.compile(r'(<|>|&lt;|&gt;|script|alert|document\.|onload\=|onerror\=|eval\(|expression\(|prompt\(|confirm\()')
    if xss_pattern.search(input_string.split("/")[-1]):
        return 1
    else:
        return 0

df["is_xss"] = df["query"].apply(xss_check)

def lfi_check(input_string):
    input_string = urllib.parse.unquote(input_string)
    lfi_pattern = re.compile(r'(file\:\/\/|(\.\.\/)|(\.\.\\))')
    if "=" in input_string.split("/")[-1]:
        if lfi_pattern.search(input_string.split("/")[-1].split("=", 1)[1]):
            return 1
        else:
            return 0
    elif lfi_pattern.search(input_string.split("/")[-1]):
        return 1
    else:
        return 0

df["is_lfi"] = df["query"].apply(lfi_check)

def command_injection_check(input_string):
    input_string = urllib.parse.unquote(input_string)
    cmd_injection_pattern = re.compile(r'(;|\||`|\$\(|\$\{)')

    if cmd_injection_pattern.search(input_string):
        return 1
    else:
        return 0

df["is_oci"] = df["query"].apply(command_injection_check)

def sql_injection_check(input_string):
    input_string = urllib.parse.unquote(input_string)
    sqli_pattern = re.compile(r'(\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR|UNION|ALL|EXEC|EXECUTE|DECLARE|CAST)\b)')

    if sqli_pattern.search(input_string):
        return 1
    else:
        return 0

df["is_sqli"] = df["query"].apply(sql_injection_check)

def semicolon_count(url):
    url = urllib.parse.unquote(url)
    return url.count(";")

df["semicolon_count"] = df["query"].apply(semicolon_count)

def underscore_count(url):
    url = urllib.parse.unquote(url)
    return url.count("_")

df["underscore_count"] = df["query"].apply(underscore_count)

def equal_count(url):
    url = urllib.parse.unquote(url)
    return url.count("=")

df["equal_count"] = df["query"].apply(equal_count)

def and_count(url):
    url = urllib.parse.unquote(url)
    return url.count("&")

df["and_count"] = df["query"].apply(equal_count)

def or_count(url):
    url = urllib.parse.unquote(url)
    return url.count("|")

df["or_count"] = df["query"].apply(or_count)

def dotcount(url):
    url = urllib.parse.unquote(url)
    return url.count(".")

df["dot_count"] = df["query"].apply(dotcount)

def atcount(url):
    url = urllib.parse.unquote(url)
    return url.count("@")

df["at_count"] = df["query"].apply(atcount)

def subdircount(url):
    url = urllib.parse.unquote(url)
    parsed_url = urllib.parse.urlparse(url)
    subdirectory_path = len(parsed_url.path.strip("/").split("/"))
    return subdirectory_path

df["subdir_count"] = df["query"].apply(subdircount)

def query_len(url):
    parsed_url = urllib.parse.urlparse(url)
    if len(parsed_url.query) > 0:
        query_params = urllib.parse.parse_qs(parsed_url.query)
        query_string = "".join(f"{value[0]}" for key, value in query_params.items())    
        return len(query_string)
    else:
        return 0

df["query_len"] = df["query"].apply(query_len)

def param_count(url):
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    return len(query_params)

df["param_count"] = df["query"].apply(param_count)

def total_digits_in_url(url):
    total_digits = 0
    for text in list(map(str, "0123456789")):
        total_digits += url.lower().count(text)
        
    return total_digits

df["total_digits_url"] = df["query"].apply(total_digits_in_url)

def total_letter_in_url(url):
    total_letter = 0
    for text in url:
        if text not in "0123456789":
            if text not in string.punctuation:
                total_letter += 1
        
    return total_letter


tokenizer = RegexpTokenizer(r"[A-Za-z]+")
df["url_tokenized"] = df["query"].apply(lambda x: tokenizer.tokenize(x))
stemmer = SnowballStemmer("english")
def stem_url(column):
    words = [stemmer.stem(word) for word in column if len(word) >= 3]
    return " ".join(words)
df["url_stemmed"] = df["url_tokenized"].apply(stem_url)
def total_digits_domain(url):
    parsed_url = urllib.parse.urlparse(url)
    clean_url = url.replace(parsed_url.query, "")
    path_components = [component for component in clean_url.split('/') if component]
    if path_components:
        until_last_directory = "".join([word for word in path_components[:-1]])
        return total_digits_in_url(until_last_directory)
    else:
        return 0
df["total_digits_domain"] = df["query"].apply(total_digits_domain)
def total_letter_domain(url):
    parsed_url = urllib.parse.urlparse(url)
    clean_url = url.replace(parsed_url.query, "")
    path_components = [component for component in clean_url.split('/') if component]
    if path_components:
        until_last_directory = "".join([word for word in path_components[:-1]])
        return total_letter_in_url(until_last_directory)
    else:
        return 0
df["total_letter_domain"] = df["query"].apply(total_letter_domain)
def total_digits_path(url):
    parsed_url = urllib.parse.urlparse(url)
    clean_url = url.replace(parsed_url.query, "")
    path_components = [component for component in clean_url.split('/') if component]
    if path_components:
        last_directory = "".join([word for word in path_components[-1]])
        return total_digits_in_url(last_directory)
    else:
        return total_digits_in_url(clean_url)
df["total_digits_path"] = df["query"].apply(total_digits_path)
def total_letter_path(url):
    parsed_url = urllib.parse.urlparse(url)
    clean_url = url.replace(parsed_url.query, "")
    path_components = [component for component in clean_url.split('/') if component]
    if path_components:
        last_directory = "".join([word for word in path_components[-1]])
        return total_letter_in_url(last_directory)
    else:
        return total_letter_in_url(clean_url)
df["total_letter_path"] = df["query"].apply(total_letter_path)
def has_extension(url):
    url = urllib.parse.unquote(url)
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    path = parsed_url.path
    file_extension = os.path.splitext(path)[1]
    if not query_params or not file_extension:
        return 0
    else:
        return 1
df["has_extension"] = df["query"].apply(has_extension)
def find_extension(url):
    url = urllib.parse.unquote(url)
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    path = parsed_url.path
    file_extension = os.path.splitext(path)[1]
    if not file_extension:
        return ""
    else:
        return file_extension
df["extension"] = df["query"].apply(find_extension)
def has_parameter(url):
    parsed_url = urllib.parse.urlparse(url)
    if len(parsed_url.query) > 0:
        return 1
    else:
        return 0
df["has_parameter"] = df["query"].apply(has_parameter)
def find_parameter_name(url):
    parsed_url = urllib.parse.urlparse(url)
    if len(parsed_url.query) > 0:
        query_params = urllib.parse.parse_qs(parsed_url.query)
        query_string = " ".join(f"{key}" for key, value in query_params.items())    
        return query_string
    else:
        return ""
def ml_predict(request):
    data = request.form if request.method == 'POST' else None
    data=[value for key,value in data.items()]
    print(data)
    headers_dict = dict(request.headers)
    headers_to_keep = ['Connection', 'Content-Length', 'Cache-Control', 'Content-Type', 'User-Agent', 'Accept', 'Referer']
    filtered_headers = {key: value for key, value in headers_dict.items() if key in headers_to_keep}
    headers = list(filtered_headers.values())

    http_uri = request.request_uri
    l = [i for i in data]
    l+=headers
    print(l)
df["parameters"] = df["query"].apply(find_parameter_name)
X = df.drop(["query", "url_tokenized", "url_stemmed", "extension", "parameters"], axis=1)
ss = StandardScaler()
X = ss.fit_transform(X)
print(X)

model_path = "flask_app\modules\ml_check.py"
model = joblib.load(model_path)
# Prediction 
prediction = model.predict(X)
print(prediction)