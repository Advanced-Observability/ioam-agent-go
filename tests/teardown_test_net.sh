#!/bin/bash

# Script to test IOAM with fake network created using network namespaces

# Remove namespaces
cleanup()
{
  ip netns delete encap || true
  ip netns delete transit || true
  ip netns delete decap || true
}

echo "Cleaning everything up..."
cleanup
echo -e "Done cleaning.\n"

