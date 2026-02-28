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

# Section 1: Core - Auth & File Upload
st.sidebar.header("Admin: Issue Certificate")
issuer_name = st.sidebar.text_input("Issuer Name")

# CORRECTED COMMAND: Using file_uploader instead of file_picker
uploaded_file = st.sidebar.file_uploader("Upload Certificate (PDF/JPG/PNG)") 

if st.sidebar.button("Issue & Hash Certificate"):
    if issuer_name and uploaded_file is not None:
        # Read the file's binary content to create a unique hash
        file_bytes = uploaded_file.getvalue()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        
        # Store metadata in the block
        data = f"Issuer: {issuer_name} | File: {uploaded_file.name} | Cert_Hash: {file_hash}"
        
        new_block = create_block(data, st.session_state.chain[-1]['hash'])
        st.session_state.chain.append(new_block)
        st.sidebar.success(f"Successfully Added: {uploaded_file.name}")
    else:
        st.sidebar.error("Missing Issuer Name or File!")


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
from transformers import AutoImageProcessor, AutoModelForImageClassification
import torch
from PIL import Image

# Load the model once (e.g., SDXL-detector)
processor = AutoImageProcessor.from_pretrained("Organika/sdxl-detector")
model = AutoModelForImageClassification.from_pretrained("Organika/sdxl-detector")

def detect_ai_generated(image):
    inputs = processor(images=image, return_tensors="pt")
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
    
    # Get prediction label
    predicted_class_idx = logits.argmax(-1).item()
    label = model.config.id2label[predicted_class_idx]
    return label
    
from PIL import Image
from PIL.ExifTags import TAGS

def check_forensics(image_file):
    img = Image.open(image_file)
    exif_data = img.getexif()
    
    if not exif_data:
        return "⚠️ WARNING: No Metadata found. Possible AI generation or stripped file."
    
    details = {}
    for tag_id in exif_data:
        tag_name = TAGS.get(tag_id, tag_id)
        details[tag_name] = exif_data.get(tag_id)
        
    # Check for common editing software signatures
    if "Software" in details:
        return f"🚨 EDITED: Created/Modified with {details['Software']}"
    from PIL import Image
from PIL.ExifTags import TAGS

def check_forensics(image_file):
    img = Image.open(image_file)
    exif_data = img.getexif()
    
    if not exif_data:
        return "⚠️ WARNING: No Metadata found. Possible AI generation or stripped file."
    
    details = {}
    for tag_id in exif_data:
        tag_name = TAGS.get(tag_id, tag_id)
        details[tag_name] = exif_data.get(tag_id)
        
    # Check for common editing software signatures
    if "Software" in details:
        return f"🚨 EDITED: Created/Modified with {details['Software']}"
        
# Advanced: Simulation of Tamper Logic
if st.button("🚨 Simulate Tamper (Break Chain)"):
    if len(st.session_state.chain) > 1:
        st.session_state.chain[1]['cert_data'] = "HACKED DATA"
        st.warning("Modified Block #1 data. Check the ledger above!")

