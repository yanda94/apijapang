
from django.http import HttpRequest, HttpResponse
from rest_framework import renderers, response

import json


class CustomRender(renderers.JSONRenderer):

    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        
        response = renderer_context['response']

        var_status = False
        var_data = None
        var_error = None
        var_code = response.status_code

        if 'ErrorDetail' in str(data):

            # overide return
            if response.status_code >= 400:
                if 'detail' in data:
                    data = data['detail']

            var_error = {
                'code': var_code,
                'message': data
            }
        else:
            var_status = True
            var_data = data

        custom_response = json.dumps({
            'status': var_status,
            'data': var_data,
            'error': var_error,
        })
        return custom_response
