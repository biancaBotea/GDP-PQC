text1=$(cat /proc/stat | head -1)

sleep 1

text2=$(cat /proc/stat | head -1)

individual1=($text1)
declare -i cBusy1=${individual1[1]}+${individual1[2]}+${individual1[3]}
declare -i cTotal1=${individual1[4]}+$cBusy1
echo $cBusy1
echo $cTotal1

individual2=($text2)
declare -i cBusy2=${individual2[1]}+${individual2[2]}+${individual2[3]}
declare -i cTotal2=${individual2[4]}+$cBusy2
echo $cBusy2
echo $cTotal2

declare -i tempH=$cBusy2-$cBusy1
echo $tempH
declare -i tempL=$cTotal2-$cTotal1
echo $tempL
