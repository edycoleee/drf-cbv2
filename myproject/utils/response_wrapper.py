#myproject/response_wrapper.py
def success_response(message=None, data=None, status="success"):
    return {
        "status": status,
        "message": message,
        "data": data if data is not None else {}
    }