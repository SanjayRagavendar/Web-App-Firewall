import pandas as pd
import re
import urllib.parse
import string
import os
from nltk.tokenize import RegexpTokenizer
from nltk.stem import SnowballStemmer
from imblearn.over_sampling import SMOTE
from sklearn.preprocessing import StandardScaler

class Preprocessor:
    def _init_(self, d):
        self.d = d
    def create_dataframe_from_list(l):
        df = pd.DataFrame(l, columns=["Data"])
        return df
    def clean_newline(self, column):
        column[:-2]
        return column[:-2]

    def clear_first_char(self, column):
        if column.startswith("/"):
            return column[1:]
        else:
            return column

    def xss_check(self, input_string):
        input_string = urllib.parse.unquote(input_string)
        xss_pattern = re.compile(r'(<|>|&lt;|&gt;|script|alert|document\.|onload\=|onerror\=|eval\(|expression\(|prompt\(|confirm\()')
        if xss_pattern.search(input_string.split("/")[-1]):
            return 1
        else:
            return 0

    def lfi_check(self, input_string):
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

    def command_injection_check(self, input_string):
        input_string = urllib.parse.unquote(input_string)
        cmd_injection_pattern = re.compile(r'(;|\||`|\$\(|\$\{)')

        if cmd_injection_pattern.search(input_string):
            return 1
        else:
            return 0

    def sql_injection_check(self, input_string):
        input_string = urllib.parse.unquote(input_string)
        sqli_pattern = re.compile(r'(\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR|UNION|ALL|EXEC|EXECUTE|DECLARE|CAST)\b)')

        if sqli_pattern.search(input_string):
            return 1
        else:
            return 0

    def semicolon_count(self, url):
        url = urllib.parse.unquote(url)
        return url.count(";")

    def underscore_count(self, url):
        url = urllib.parse.unquote(url)
        return url.count("_")

    def equal_count(self, url):
        url = urllib.parse.unquote(url)
        return url.count("=")

    def and_count(self, url):
        url = urllib.parse.unquote(url)
        return url.count("&")

    def or_count(self, url):
        url = urllib.parse.unquote(url)
        return url.count("|")

    def dot_count(self, url):
        url = urllib.parse.unquote(url)
        return url.count(".")

    def at_count(self, url):
        url = urllib.parse.unquote(url)
        return url.count("@")

    def subdir_count(self, url):
        url = urllib.parse.unquote(url)
        parsed_url = urllib.parse.urlparse(url)
        subdirectory_path = len(parsed_url.path.strip("/").split("/"))
        return subdirectory_path

    def query_len(self, url):
        parsed_url = urllib.parse.urlparse(url)
        if len(parsed_url.query) > 0:
            query_params = urllib.parse.parse_qs(parsed_url.query)
            query_string = "".join(f"{value[0]}" for key, value in query_params.items())
            return len(query_string)
        else:
            return 0

    def param_count(self, url):
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        return len(query_params)

    def total_digits_in_url(self, url):
        total_digits = 0
        for text in list(map(str, "0123456789")):
            total_digits += url.lower().count(text)

        return total_digits

    def total_letter_in_url(self, url):
        total_letter = 0
        for text in url:
            if text not in "0123456789":
                if text not in string.punctuation:
                    total_letter += 1

        return total_letter

    def total_digits_domain(self, url):
        parsed_url = urllib.parse.urlparse(url)
        clean_url = url.replace(parsed_url.query, "")
        path_components = [component for component in clean_url.split('/') if component]
        if path_components:
            until_last_directory = "".join([word for word in path_components[:-1]])
            return self.total_digits_in_url(until_last_directory)
        else:
            return 0

    def total_letter_domain(self, url):
        parsed_url = urllib.parse.urlparse(url)
        clean_url = url.replace(parsed_url.query, "")
        path_components = [component for component in clean_url.split('/') if component]
        if path_components:
            until_last_directory = "".join([word for word in path_components[:-1]])
            return self.total_letter_in_url(until_last_directory)
        else:
            return 0

    def total_digits_path(self, url):
        parsed_url = urllib.parse.urlparse(url)
        clean_url = url.replace(parsed_url.query, "")
        path_components = [component for component in clean_url.split('/') if component]
        if path_components:
            last_directory = "".join([word for word in path_components[-1]])
            return self.total_digits_in_url(last_directory)
        else:
            return self.total_digits_in_url(clean_url)

    def total_letter_path(self, url):
        parsed_url = urllib.parse.urlparse(url)
        clean_url = url.replace(parsed_url.query, "")
        path_components = [component for component in clean_url.split('/') if component]
        if path_components:
            last_directory = "".join([word for word in path_components[-1]])
            return self.total_letter_in_url(last_directory)
        else:
            return self.total_letter_in_url(clean_url)

    def has_extension(self, url):
        url = urllib.parse.unquote(url)
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        path = parsed_url.path
        file_extension = os.path.splitext(path)[1]
        if not query_params or not file_extension:
            return 0
        else:
            return 1

    def find_extension(self, url):
        url = urllib.parse.unquote(url)
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        path = parsed_url.path
        file_extension = os.path.splitext(path)[1]
        if not file_extension:
            return ""
        else:
            return file_extension

    def has_parameter(self, url):
        parsed_url = urllib.parse.urlparse(url)
        if len(parsed_url.query) > 0:
            return 1
        else:
            return 0

    def find_parameter_name(self, url):
        parsed_url = urllib.parse.urlparse(url)
        if len(parsed_url.query) > 0:
            query_params = urllib.parse.parse_qs(parsed_url.query)
            query_string = " ".join(f"{key}" for key, value in query_params.items())
            return query_string
        else:
            return ""

    def analyze(self):
        self.df["query"] = self.df["query"].apply(self.clean_newline)
        self.df["query"] = self.df["query"].apply(self.clear_first_char)
        self.df["is_xss"] = self.df["query"].apply(self.xss_check)
        self.df["is_lfi"] = self.df["query"].apply(self.lfi_check)
        self.df["is_oci"] = self.df["query"].apply(self.command_injection_check)
        self.df["is_sqli"] = self.df["query"].apply(self.sql_injection_check)
        self.df["semicolon_count"] = self.df["query"].apply(self.semicolon_count)
        self.df["underscore_count"] = self.df["query"].apply(self.underscore_count)
        self.df["equal_count"] = self.df["query"].apply(self.equal_count)
        self.df["and_count"] = self.df["query"].apply(self.equal_count)
        self.df["or_count"] = self.df["query"].apply(self.or_count)
        self.df["dot_count"] = self.df["query"].apply(self.dot_count)
        self.df["at_count"] = self.df["query"].apply(self.at_count)
        self.df["subdir_count"] = self.df["query"].apply(self.subdir_count)
        self.df["query_len"] = self.df["query"].apply(self.query_len)
        self.df["param_count"] = self.df["query"].apply(self.param_count)
        self.df["total_digits_url"] = self.df["query"].apply(self.total_digits_in_url)
        self.df["total_letter_url"] = self.df["query"].apply(self.total_letter_in_url)
        self.df["total_digits_domain"] = self.df["query"].apply(self.total_digits_domain)
        self.df["total_letter_domain"] = self.df["query"].apply(self.total_letter_domain)
        self.df["total_digits_path"] = self.df["query"].apply(self.total_digits_path)
        self.df["total_letter_path"] = self.df["query"].apply(self.total_letter_path)
        self.df["has_extension"] = self.df["query"].apply(self.has_extension)
        self.df["extension"] = self.df["query"].apply(self.find_extension)
        self.df["has_parameter"] = self.df["query"].apply(self.has_parameter)
        self.df["parameters"] = self.df["query"].apply(self.find_parameter_name)

        # Tokenization and stemming
        tokenizer = RegexpTokenizer(r"[A-Za-z]+")
        self.df["url_tokenized"] = self.df["query"].apply(lambda x: tokenizer.tokenize(x))
        stemmer = SnowballStemmer("english")
        self.df["url_stemmed"] = self.df["url_tokenized"].apply(lambda x: " ".join([stemmer.stem(word) for word in x if len(word) >= 3]))

        # Continue with the remaining code...
        X = self.df.drop(["query", "label", "url_tokenized", "url_stemmed", "extension", "parameters"], axis=1)
        ss = StandardScaler()
        X = ss.fit_transform(X)

        # Apply SMOTE
        smote = SMOTE(random_state=42)
        X_resampled, _ = smote.fit_resample(X, self.df["label"])

        return X_resampled
    
def ml_predict(request):
        data = request.form if request.method == 'POST' else None
        headers_dict = dict(request.headers)
        headers = list(headers_dict.values())
        http_uri = request.request_uri
        l = [data, http_uri]
        l += headers
        pred=ml_predict()
        preprocessor=Preprocessor(df=l)
        X_resampled=preprocessor.analyze()
        print(X_resampled)
        if X_resampled >0.5:
            return 1
        else:
            return 0

