flows=$1
flow=0
while (( flow < flows ));do
	((core=16+4*flow))
	((port=4000+flow))
	taskset -c 16 ./netdriver_test 192.168.10.117:$port --sp $((1000+core)) --count 1 ndping &
	((flow++))
done
