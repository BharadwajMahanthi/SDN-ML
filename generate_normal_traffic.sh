#!/bin/bash
# Generate normal SDN traffic patterns

echo "Generating normal traffic patterns..."

# Test connectivity
echo "Testing connectivity between hosts..."
docker exec clab-sdn-attack-lab-h1 ping -c 10 10.0.0.2 &
docker exec clab-sdn-attack-lab-h1 ping -c 10 10.0.0.3 &
docker exec clab-sdn-attack-lab-h2 ping -c 10 10.0.0.4 &

wait

# Generate UDP traffic
echo "Generating UDP traffic..."
for i in {1..20}; do
    docker exec clab-sdn-attack-lab-h1 sh -c "echo 'test traffic' | nc -u -w 1 10.0.0.2 5000" || true
    docker exec clab-sdn-attack-lab-h3 sh -c "echo 'test traffic' | nc -u -w 1 10.0.0.4 5000" || true
    sleep 2
done

echo "Normal traffic generation complete!"
