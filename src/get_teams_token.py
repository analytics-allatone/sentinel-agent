import os
import time
import httpx

CLIENT_ID = os.getenv("MS_TEAMS_CLIENT_ID") or input("Client ID: ").strip()
TENANT = os.getenv("MS_TEAMS_TENANT_ID") or input("Tenant ID (or 'common'): ").strip() or "common"
SCOPE = "offline_access ChannelMessage.Send"
BASE = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0"


def main():
    with httpx.Client(timeout=30) as c:
        dc = c.post(f"{BASE}/devicecode",
                    data={"client_id": CLIENT_ID, "scope": SCOPE})
        dc.raise_for_status()
        d = dc.json()

        print("\n" + "=" * 60)
        print(d["message"])          # "Go to https://microsoft.com/devicelogin and enter CODE"
        print("=" * 60 + "\n")

        interval = int(d.get("interval", 5))
        while True:
            time.sleep(interval)
            tok = c.post(f"{BASE}/token", data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": CLIENT_ID,
                "device_code": d["device_code"],
            })
            j = tok.json()
            if tok.status_code == 200:
                print("\nSUCCESS. Put this in your .env:\n")
                print(f"MS_TEAMS_TENANT_ID={TENANT}")
                print(f"MS_TEAMS_CLIENT_ID={CLIENT_ID}")
                print(f"MS_TEAMS_REFRESH_TOKEN={j['refresh_token']}")
                return
            err = j.get("error")
            if err == "authorization_pending":
                continue            # user hasn't finished login yet
            if err == "slow_down":
                interval += 5
                continue
            print("Failed:", j.get("error_description", j))
            return


if __name__ == "__main__":
    main()
