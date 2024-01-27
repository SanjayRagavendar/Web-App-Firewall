def ml_predict(request):
    data = request.form if request.method == 'POST' else None
    headers_dict = dict(request.headers)
    headers=headers_dict.values()
    http_uri = request.request_uri
    l=[data,http_uri]
    l+=headers
    