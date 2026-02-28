import streamlit as st
import hashlib
import json
from datetime import datetime

# --- BLOCKCHAIN LOGIC ---
def generate_hash(block):
    # Standard SHA-256 Hashing
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def create_block(data, prev_hash):
    block = {
        'index': len(st.session_state.chain) + 1,
        'timestamp': str(datetime.now()),
        'cert_data': data,
        'prev_hash': prev_hash
    }
    block['hash'] = generate_hash(block)
    return block

# --- APP STATE ---
if 'chain' not in st.session_state:
    # Initial "Genesis" Block
    genesis = {'index': 0, 'timestamp': str(datetime.now()), 'cert_data': "Genesis", 'prev_hash': "0"}
    genesis['hash'] = generate_hash(genesis)
    st.session_state.chain = [genesis]

# --- UI LAYOUT ---
st.title("🛡️ Blockchain Certificate System")
st.markdown("---")

# Section 1: Core - Auth & Upload
st.sidebar.header("Admin: Issue Certificate")
issuer_name = st.sidebar.text_input("Issuer Name")
student_id = st.sidebar.text_input("Student ID/Name")

if st.sidebar.button("Issue & Hash Certificate"):
    if issuer_name and student_id:
        data = f"Issuer: {issuer_name} | Recipient: {student_id}"
        new_block = create_block(data, st.session_state.chain[-1]['hash'])
        st.session_state.chain.append(new_block)
        st.sidebar.success("Certificate Added to Blockchain!")
    else:
        st.sidebar.error("Fill in all fields")

# Section 2: Core - Verification Lookup
st.header("🔍 Verification Lookup")
search_hash = st.text_input("Paste Certificate Hash to Verify")

if search_hash:
    match = next((b for b in st.session_state.chain if b['hash'] == search_hash), None)
    if match:
        st.success(f"✅ Authentic! Found: {match['cert_data']}")
    else:
        st.error("❌ Certificate Not Found/Invalid.")

# Section 3: Advanced - Hash Chain Simulation & Tamper Detection
st.header("⛓️ Live Blockchain Ledger")

for i, block in enumerate(st.session_state.chain):
    with st.expander(f"Block #{block['index']} - Hash: {block['hash'][:15]}..."):
        # TAMPER LOGIC: Check if this block's hash still matches its data
        temp_block = block.copy()
        temp_block.pop('hash')
        current_calc_hash = generate_hash(temp_block)
        
        # Check link to previous
        link_broken = False
        if i > 0 and block['prev_hash'] != st.session_state.chain[i-1]['hash']:
            link_broken = True

        if current_calc_hash != block['hash'] or link_broken:
            st.error("⚠️ STATUS: TAMPERED / INVALID")
        else:
            st.success("✅ STATUS: SECURE")
            
        st.json(block)

# Advanced: Simulation of Tamper Logic
if st.button("🚨 Simulate Tamper (Break Chain)"):
    if len(st.session_state.chain) > 1:
        st.session_state.chain[1]['cert_data'] = "HACKED DATA"
        st.warning("Modified Block #1 data. Check the ledger above!")

