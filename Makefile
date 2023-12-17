all: AS User

AS: AS.c
	gcc -o AS AS.c

User: User.c
	gcc -o User User.c

clean:
	rm -f AS User