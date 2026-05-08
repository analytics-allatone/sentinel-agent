import asyncssh

async def validate_ssh(host:str , port:int , username:str , password:str|None , client_key:str|None , auth_type:str = "password"):
    try:
        if auth_type == "key":
            async with asyncssh.connect(
                host,
                port=port,
                username=username,
                client_keys=[client_key],
                known_hosts=None
            ):
                return True
        elif auth_type == "password":
            async with asyncssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                known_hosts=None
            ):
                return True
        else:
            return False


    except Exception as e:
        return False