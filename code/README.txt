Because several files are shared among all entities we
  used soft and hard links so we only needed to update one file.
Our server were dockerized, in consequence, because the docker
  build command doesn't follow symbolic links we need to replace the
  symlinks for the original folders.

1. Run cpOriginal.sh to replace symbolic links for their original
  content

2. cd into manager/

3. docker build -t manager_img

4. cd into repository/

5. docker build -t repo_img

6. docker start -i --name manager --network=host manager_img

    password: p1g2passoword

7. docker start -i --name repo --network=host repo_img

    password: p1g2passoword

8. cd into client/
9. python3 main.py
