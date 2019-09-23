echo "This script DELETES several files presumed to be from previous tests."
echo "Check you are not in an important directory before running this"
read -r -n 1 -p "Continue? [y/N]"
if [ "$REPLY" = "y" ]
then

	# Clean up bitpoints files
	rm bitpoints.10.*
	rm bp*.*
	# Clean up receipt files
	rm bank_receipt.*.*

	# Clean up previous run files
	rm mint2
	rm pwds

	# Configurations
	certPath="certs/signed_certs/5001cert"
	keyPath="certs/signed_certs/5001pk"

	badCert="certs/signed_certs/6001cert"

	echo =================== PrintingPress create ===================
	python3 PrintingPress.py create $certPath $keyPath mint2

	echo =================== PrintingPress mint ===================
	python3 PrintingPress.py mint 10:10 $certPath mint2

	bitpointsfile="$(ls | grep bitpoints | head -1)"

	echo =================== PrintingPress info ===================
	python3 PrintingPress.py info $bitpointsfile

	echo =================== PrintingPress validate ===================
	python3 PrintingPress.py validate $bitpointsfile $certPath

	echo =================== BankCore full_test ===================
	python3 BankCore.py test $certPath $keyPath $bitpointsfile $badCert

	echo =================== BankCore balances ===================
	python3 BankCore.py balances $certPath test_bankcore_db

	echo =================== OnlineBank pw user add ===================
	echo Adding user fadyuser
	python3 OnlineBank.py pw pwds user add fadyuser
	echo Adding user sethuser
	python3 OnlineBank.py pw pwds user add sethuser

	echo =================== OnlineBank pw account add ===================
	python3 OnlineBank.py pw pwds account add "Fady'sPEM"
	# matching account names with those in BankCore's full_test

	echo =================== OnlineBank pw chmod ===================
	python3 OnlineBank.py pw pwds chmod fadyuser "Fady'sPEM" btwda
	python3 OnlineBank.py pw pwds chmod sethuser "Fady'sPEM" b
	python3 OnlineBank.py pw pwds chmod sethuser "VAULT" btwda
	python3 OnlineBank.py pw pwds chmod sethuser "__admin__" BSAFC

	echo fadyuser Permissions:
	python3 OnlineBank.py pw pwds chmod fadyuser
	echo sethuser Permissions:
	python3 OnlineBank.py pw pwds chmod sethuser

	echo =================== OnlineBank server ===================
	python3 OnlineBank.py server pwds test_bankcore_db $certPath $certPath

	#echo =================== OnlineBank Client ===================
	#python3 OnlineBank.py client 20174.1337.1337.1 $certPath fadyuser
fi
