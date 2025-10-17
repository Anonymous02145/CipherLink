#!/usr/bin/env python3
"""
Test script for port forwarding functionality
Run this to verify UPnP works on your network before integrating
"""

import sys
import time
import socket

try:
    from port_forwarding import PortForwardingManager, ConnectionTracker, PublicIPConnectionManager
except ImportError:
    print("[-] Error: Could not import port_forwarding module")
    print("    Make sure port_forwarding.py is in the same directory")
    sys.exit(1)

def test_upnp_discovery():
    """Test 1: UPnP device discovery"""
    print("\n" + "="*60)
    print("TEST 1: UPnP Device Discovery")
    print("="*60)

    manager = PortForwardingManager()

    print("[+] Attempting to discover UPnP devices...")
    if manager.initialize_upnp():
        print(f"[✓] UPnP initialized successfully!")
        print(f"    External IP: {manager.public_ip}")
        return manager
    else:
        print("[✗] UPnP initialization failed")
        print("    Possible causes:")
        print("    - UPnP disabled on router")
        print("    - Firewall blocking UPnP")
        print("    - No UPnP-capable router on network")
        return None

def test_port_forward(manager, test_port=9999):
    """Test 2: Add and verify port forward"""
    print("\n" + "="*60)
    print("TEST 2: Port Forward Creation")
    print("="*60)

    print(f"[+] Adding port forward for port {test_port}...")
    external_port = manager.add_port_forward(
        local_port=test_port,
        protocol='TCP',
        description='CipherLink_Test'
    )

    if external_port:
        print(f"[✓] Port forward created successfully!")
        print(f"    {manager.public_ip}:{external_port} -> localhost:{test_port}")

        # Verify
        print(f"[+] Verifying port forward...")
        if manager.verify_forward(external_port):
            print(f"[✓] Port forward verified!")
            return external_port
        else:
            print(f"[✗] Port forward verification failed")
            return None
    else:
        print(f"[✗] Failed to create port forward")
        return None

def test_connection_tracking(manager, test_port=9999):
    """Test 3: Connection tracking and auto-cleanup"""
    print("\n" + "="*60)
    print("TEST 3: Connection Tracking & Auto-Cleanup")
    print("="*60)

    tracker = ConnectionTracker(manager)

    # Simulate multiple connections
    print("[+] Simulating 3 connections on port", test_port)

    tracker.register_connection("conn1", test_port)
    print(f"    Connection 1 registered (ref count: {tracker.port_ref_count.get(test_port, 0)})")

    tracker.register_connection("conn2", test_port)
    print(f"    Connection 2 registered (ref count: {tracker.port_ref_count.get(test_port, 0)})")

    tracker.register_connection("conn3", test_port)
    print(f"    Connection 3 registered (ref count: {tracker.port_ref_count.get(test_port, 0)})")

    # Verify port still forwarded
    if manager.verify_forward(test_port):
        print(f"[✓] Port forward active with multiple connections")

    # Close connections one by one
    print("\n[+] Closing connections...")

    tracker.unregister_connection("conn1")
    print(f"    Connection 1 closed (ref count: {tracker.port_ref_count.get(test_port, 0)})")
    time.sleep(1)

    if manager.verify_forward(test_port):
        print(f"[✓] Port forward still active (2 connections remaining)")

    tracker.unregister_connection("conn2")
    print(f"    Connection 2 closed (ref count: {tracker.port_ref_count.get(test_port, 0)})")
    time.sleep(1)

    if manager.verify_forward(test_port):
        print(f"[✓] Port forward still active (1 connection remaining)")

    tracker.unregister_connection("conn3")
    print(f"    Connection 3 closed (ref count: {tracker.port_ref_count.get(test_port, 0)})")
    time.sleep(2)  # Give time for cleanup

    # Verify port forward removed
    if not manager.verify_forward(test_port):
        print(f"[✓] Port forward automatically removed after last connection closed!")
        return True
    else:
        print(f"[✗] Port forward still active (should be removed)")
        return False

def test_socket_binding(test_port=9999):
    """Test 4: Actual socket binding on test port"""
    print("\n" + "="*60)
    print("TEST 4: Socket Binding")
    print("="*60)

    try:
        print(f"[+] Creating listening socket on port {test_port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', test_port))
        sock.listen(1)
        sock.settimeout(5)

        print(f"[✓] Socket bound successfully on 0.0.0.0:{test_port}")
        print(f"    Listening for connections...")
        print(f"    (Timeout: 5 seconds)")

        try:
            conn, addr = sock.accept()
            print(f"[✓] Received connection from {addr}")
            conn.close()
        except socket.timeout:
            print(f"[i] No incoming connections (this is normal for automated test)")

        sock.close()
        return True

    except Exception as e:
        print(f"[✗] Socket binding failed: {e}")
        return False

def test_public_ip_manager():
    """Test 5: Full PublicIPConnectionManager"""
    print("\n" + "="*60)
    print("TEST 5: PublicIPConnectionManager Integration")
    print("="*60)

    manager = PublicIPConnectionManager()

    print("[+] Enabling public IP mode...")
    if manager.enable_public_ip_mode():
        print("[✓] Public IP mode enabled successfully!")

        test_port = 9998
        print(f"\n[+] Setting up listener on port {test_port}...")
        address, port = manager.setup_listener(test_port)

        if address and port:
            print(f"[✓] Listener setup successful!")
            print(f"    Address: {address}:{port}")

            # Simulate connection lifecycle
            print(f"\n[+] Simulating connection lifecycle...")
            manager.on_connection_established("test_conn", test_port)
            print(f"    Connection established")

            time.sleep(2)

            manager.on_connection_closed("test_conn")
            print(f"    Connection closed")

            time.sleep(2)

            print(f"[✓] Connection lifecycle test complete!")
            return True
        else:
            print(f"[✗] Listener setup failed")
            return False
    else:
        print("[✗] Failed to enable public IP mode")
        return False

def cleanup_test_forwards(manager):
    """Cleanup any test port forwards"""
    print("\n" + "="*60)
    print("CLEANUP: Removing test port forwards")
    print("="*60)

    test_ports = [9999, 9998]
    for port in test_ports:
        if manager.remove_port_forward(port):
            print(f"[+] Removed port forward for {port}")

    manager.list_forwards()

def main():
    """Run all tests"""
    print("""
╔══════════════════════════════════════════════════════════╗
║     CipherLink Port Forwarding Test Suite               ║
║                                                          ║
║  This script will test UPnP port forwarding on your     ║
║  network to ensure the feature works correctly.         ║
╚══════════════════════════════════════════════════════════╝
    """)

    print("[!] Prerequisites:")
    print("    - UPnP must be enabled on your router")
    print("    - No firewall blocking UPnP discovery")
    print("    - miniupnpc library installed (pip install miniupnpc)")

    input("\nPress Enter to start tests...")

    results = {}

    # Test 1: UPnP Discovery
    manager = test_upnp_discovery()
    results['upnp_discovery'] = manager is not None

    if not manager:
        print("\n" + "="*60)
        print("FATAL: Cannot proceed without UPnP")
        print("="*60)
        print("\nPlease enable UPnP on your router and try again.")
        print("Refer to the installation guide for router-specific instructions.")
        sys.exit(1)

    # Test 2: Port Forward Creation
    external_port = test_port_forward(manager, 9999)
    results['port_forward'] = external_port is not None

    # Test 3: Connection Tracking
    if external_port:
        results['connection_tracking'] = test_connection_tracking(manager, 9999)
    else:
        results['connection_tracking'] = False
        print("\n[SKIP] Skipping connection tracking test (port forward failed)")

    # Test 4: Socket Binding
    results['socket_binding'] = test_socket_binding(9999)

    # Test 5: Full Manager
    results['full_manager'] = test_public_ip_manager()

    # Cleanup
    cleanup_test_forwards(manager)
    manager.remove_all_forwards()

    # Results Summary
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)

    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result)

    for test_name, result in results.items():
        status = "[✓ PASS]" if result else "[✗ FAIL]"
        print(f"{status} {test_name.replace('_', ' ').title()}")

    print("="*60)
    print(f"Total: {passed_tests}/{total_tests} tests passed")
    print("="*60)

    if passed_tests == total_tests:
        print("\n[✓] All tests passed! Your system is ready for public IP connections.")
        return 0
    else:
        print(f"\n[!] {total_tests - passed_tests} test(s) failed. Please check the output above.")
        print("    Common issues:")
        print("    - UPnP not enabled on router")
        print("    - Firewall blocking UPnP")
        print("    - Port already in use")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n[!] Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[✗] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
