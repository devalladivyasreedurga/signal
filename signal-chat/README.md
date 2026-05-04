# UIC Signal

## Prerequisites

**macOS**
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install python3 node redis
```

**Ubuntu/Debian**
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nodejs npm redis-server
```

## Run

```bash
./run.sh
```

Opens backend on `http://localhost:5001` and frontend on `http://localhost:3000`.

## If `run.sh` fails

Start each service manually in separate terminals:

```bash
# Terminal 1
redis-server

# Terminal 2
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m server.app

# Terminal 3
cd frontend
npm install
npm run dev
```

## Testing

Open `http://localhost:3000` in two browser windows — one normal, one private (incognito).

**Setup**
1. Window 1: Register as `alice`, then log in
2. Window 2: Register as `bob`, then log in

**Online messaging**
1. Alice selects Bob from the sidebar and sends a message
2. Bob receives and decrypts it in real time
3. Reply from Bob back to Alice — confirm both sides decrypt correctly

**Offline delivery**
1. Log Bob out (close window 2 or log out)
2. Alice sends several messages to Bob
3. Log Bob back in — all messages appear immediately on login

**Verify encryption**
- Open the Developer Panel (bottom-left button) on either window
- Check the **X3DH** tab: Alice shows `INITIATOR`, Bob shows `RESPONDER`, both show the same SK
- Check the **Server View** tab: the payload column shows only random-looking ciphertext, no readable words
