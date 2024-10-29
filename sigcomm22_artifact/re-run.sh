sudo rmmod nd_module
cd ~/NetChannel/module/
make clean && make -j9
cd ~/NetChannel/util/
make clean && make -j9
cd ~/NetChannel/scripts
./pre-run.sh
#最后要在两个均运行完以上脚本后运行sudo ~/NetChannel/scripts/run_module.sh