if [ -f "webhooks.bash" ]; then
  source webhooks.bash
fi

while :
do
  python mqtt.py
  sleep 15
done
