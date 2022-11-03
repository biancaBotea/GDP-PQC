text=$(cat /proc/stat | head -1)
individual=($text)
declare -i cBusy=${individual[1]}+${individual[2]}+${individual[3]}
declare -i cTotal=${individual[4]}+$cBusy
echo $cBusy
echo $cTotal

sleep 1

text=$(cat /proc/stat | head -1)
individual=($text)
declare -i cBusy1=${individual[1]}+${individual[2]}+${individual[3]}
declare -i cTotal1=${individual[4]}+$cBusy
echo $cBusy1
echo $cTotal1

declare -i tempH=$cBusy1-$cBusy
echo $tempH
declare -i tempL=$cTotal1-$cTotal
echo $tempL
