# pw: testtest

# Clean up bitpoints files
rm bitpoints.10.*

echo =================== PrintingPress create ===================
python3 PrintingPress.py create certs/signed_certs/5001cert certs/signed_certs/5001pk mint2

echo =================== PrintingPress mint ===================
python3 PrintingPress.py mint 10:10 certs/signed_certs/5001cert mint2

bitpointsfile="$(ls | grep bitpoints)"

echo =================== PrintingPress info ===================
python3 PrintingPress.py info $bitpointsfile

echo =================== PrintingPress validate ===================
python3 PrintingPress.py validate $bitpointsfile certs/signed_certs/5001cert

# pw: banking

echo =================== BankCore full_test ===================
python3 BankCore.py test certs/signed_certs/5001cert certs/signed_certs/5001pk $bitpointsfile certs/signed_certs/6001cert

echo =================== BankCore balances ===================
python3 BankCore.py balances certs/signed_certs/5001cert test_bankcore_db

# pw: userpw
echo =================== OnlineBank pw user add ===================
echo Adding user fadyuser
python3 OnlineBank.py pw pwds user add fadyuser
echo Adding user sethuser
python3 OnlineBank.py pw pwds user add sethuser

echo =================== OnlineBank pw account add ===================
python3 OnlineBank.py pw pwds account add "Fady'sPEM"
# match account names with that in BankCore's full_test

python3 OnlineBank.py pw pwds account add "VAULT"

echo =================== OnlineBank pw chmod ===================
python3 OnlineBank.py pw pwds chmod fadyuser
python3 OnlineBank.py pw pwds chmod fadyuser "Fady'sPEM" btwda
python3 OnlineBank.py pw pwds chmod sethuser "VAULT" btwda

echo =================== OnlineBank server ===================
python3 OnlineBank.py server pwds test_bankcore_db certs/signed_certs/5001cert certs/signed_certs/5001cert

#echo =================== OnlineBank Client ===================
#python3 OnlineBank.py client 20174.x.x.x certs/signed_certs/5001cert fadyuser
