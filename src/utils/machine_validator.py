import asyncssh

async def validate_ssh(host:str , username:str , password:str|None , private_key:str|None ,port:int = 22, auth_type:str = "password"):
    try:
        if auth_type == "key":
            if private_key:
                # This parses the string content of the private key
                private_key = asyncssh.import_private_key(private_key)
            else:
                return False
            async with asyncssh.connect(
                host,
                port=port,
                username=username,
                client_keys=[private_key],
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
    



async def run_ssh_command(host: str, username: str, command: str, password: str|None = None, private_key: str|None = None, port: int = 22, auth_type: str = "password"):
    try:
        # Prepare Auth
        connect_params = {
            "host": host,
            "port": port,
            "username": username,
            "known_hosts": None
        }

        if auth_type == "key" and private_key:
            connect_params["client_keys"] = [asyncssh.import_private_key(private_key)]
        elif auth_type == "password":
            connect_params["password"] = password

        # Connect and Execute
        async with asyncssh.connect(**connect_params) as conn:
            result = await conn.run(command, check=True)
            
            # .stdout contains the successful output
            # .stderr contains any error messages
            if result.stdout:
                return f"SUCCESS:\n{result.stdout}"
            else:
                return f"EMPTY RESULT / ERRORS:\n{result.stderr}"

    except Exception as e:
        return f"CONNECTION FAILED: {str(e)}"

# Example usage:
# output = await run_ssh_command("192.168.1.10", "admin", "whoami")
# print(output)