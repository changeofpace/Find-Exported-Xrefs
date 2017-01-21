## Summary:
Given a global name, find all xrefs which are contained in an exported function.

## How to use:
1. Click a global name.
2. Run the script.

## Sample output:

ntoskrnl!SeDebugPrivilege 

<pre>
PAGEDATA:00000001405460B0 SeDebugPrivilege dq 0
</pre>

<pre>
================================================================================
Dumping exported xrefs for:  SeDebugPrivilege  0x1405460b0
================================================================================
0x1403d1781  NtSetInformationThread + 0x88011
0x1403d43a8  NtSetInformationProcess + 0x65E0C
0x1403d4823  NtSetInformationProcess + 0x66287
</pre>