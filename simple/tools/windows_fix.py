"""Simple fix for Windows ConnectionResetError [WinError 10054]"""
# a common Windows asyncio issue with ConnectionResetError: [WinError 10054]. This happens when clients (browsers) abruptly close SSL connections and the server tries to clean up an already-closed socket.

# Optional import - won't crash if the tools folder or module doesn't exist
# try:
#     from tools.windows_fix import suppress_connection_errors
#     suppress_connection_errors()  # Apply fix if available
# except ImportError:
#     pass  # Silently continue without the fix


import sys

def suppress_connection_errors():
    """Suppress Windows connection reset errors by patching the problematic method"""
    if sys.platform.startswith('win'):
        import asyncio
        from asyncio.proactor_events import _ProactorBasePipeTransport
        
        # Save the original method
        original_call_connection_lost = _ProactorBasePipeTransport._call_connection_lost
        
        def patched_call_connection_lost(self, exc):
            try:
                original_call_connection_lost(self, exc)
            except (ConnectionResetError, OSError):
                # Ignore connection reset errors during cleanup
                pass
        
        # Apply the patch
        _ProactorBasePipeTransport._call_connection_lost = patched_call_connection_lost