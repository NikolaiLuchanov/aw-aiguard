import subprocess, time, os, httpx

PROJECT = '/Users/nikolail/projects/aw-aiguard'
os.chdir(PROJECT)

subprocess.run(['pkill', '-f', 'uvicorn|mock_'])
time.sleep(1)

p_g = subprocess.Popen(['venv/bin/python3', 'mock_guardian.py'])
p_l = subprocess.Popen(['venv/bin/python3', 'mock_llm.py'])
p_p = subprocess.Popen(['venv/bin/python3', '-m', 'uvicorn', 'gateway.main:app', '--host', '0.0.0.0', '--port', '9020'])

time.sleep(4)
print('Services started. Testing Phase 1.5 (HITL)...\n')

async def run_tests():
    async with httpx.AsyncClient() as client:
        # Test 1: HITL Pause (Irreversible action)
        print('Test 1: HITL Pause (delete_file)')
        r = await client.post('http://localhost:9020/v1/chat/completions', json={'messages': [{'role': 'user', 'content': 'Please delete_file /important/data'}]})
        print(f'  Status: {r.status_code} | {"PASS" if r.status_code == 202 else "FAIL"}')
        data = r.json()
        print(f'  Body: {data}')
        request_id = data.get('request_id')

        # Test 2: Check Status (Pending)
        if request_id:
            print('\nTest 2: Check Status (Pending)')
            r = await client.get(f'http://localhost:9020/hitl/status/{request_id}')
            print(f'  Status: {r.status_code} | {"PASS" if r.json().get("status") == "pending" else "FAIL"}')
            print(f'  Body: {r.json()}')

            # Test 3: Approve
            print('\nTest 3: HITL Approve')
            r = await client.post(f'http://localhost:9020/hitl/approve', json={'request_id': request_id})
            print(f'  Status: {r.status_code} | {"PASS" if r.status_code == 200 else "FAIL"}')
            print(f'  Body: {r.json()}')

            # Test 4: Check Status (Approved)
            print('\nTest 4: Check Status (Approved)')
            r = await client.get(f'http://localhost:9020/hitl/status/{request_id}')
            print(f'  Status: {r.status_code} | {"PASS" if r.json().get("status") == "approved" else "FAIL"}')

        # Test 5: HITL Pause & Deny
        print('\nTest 5: HITL Pause (git push)')
        r = await client.post('http://localhost:9020/v1/chat/completions', json={'messages': [{'role': 'user', 'content': 'git push origin main'}]})
        print(f'  Status: {r.status_code} | {"PASS" if r.status_code == 202 else "FAIL"}')
        data = r.json()
        request_id = data.get('request_id')
        if request_id:
            print('\nTest 6: HITL Deny')
            r = await client.post(f'http://localhost:9020/hitl/deny', json={'request_id': request_id})
            print(f'  Status: {r.status_code} | {"PASS" if r.status_code == 200 else "FAIL"}')

        # Test 7: Normal request (No HITL)
        print('\nTest 7: Normal request (No HITL)')
        r = await client.post('http://localhost:9020/v1/chat/completions', json={'messages': [{'role': 'user', 'content': 'What is 2+2?'}]})
        print(f'  Status: {r.status_code} | {"PASS" if r.status_code == 200 else "FAIL"}')

import asyncio
asyncio.run(run_tests())

p_g.terminate(); p_l.terminate(); p_p.terminate()
print('\nDone.')
