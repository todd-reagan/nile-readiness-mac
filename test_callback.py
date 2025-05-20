# Simple test script to simulate callback behavior

class MockPacket:
    def __init__(self, data):
        self.data = data

def test_callback(pkt):
    print("Packet received")
    return True

# Test with a simple packet
pkt = MockPacket("test data")
result = test_callback(pkt)
print(f"Result: {result}")

# Test with a lambda function
sniff_count = 0
def sniff_mock(iface=None, filter=None, prn=None, stop_filter=None, timeout=None, count=None, store=None):
    global sniff_count
    sniff_count += 1
    if prn:
        result = prn(pkt)
        print(f"Callback result: {result}")
    return [pkt]

# Mock the sniffing
print("\nTesting with mock sniff function:")
pkts = sniff_mock(prn=test_callback)
print(f"Sniff count: {sniff_count}")

# Now let's test with a modified callback that doesn't return anything
print("\nTesting with modified callback:")
def modified_callback(pkt):
    print("Modified callback received packet")
    # Process packet but don't return anything
    if pkt.data == "test data":
        print("Found test data")
    # No return statement

# Test the modified callback
pkts = sniff_mock(prn=modified_callback)
print(f"Sniff count: {sniff_count}")
