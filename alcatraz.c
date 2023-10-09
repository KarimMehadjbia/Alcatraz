/*  INF3173 - TP0 
 *  Session : automne 2021
 *  Tous les groupes
 *  
 *  IDENTIFICATION.
 *
 *      Nom : Mehadjbia Dia
 *      Prénom : Karim
 *      Code permanent : MEHK92050004
 *      Groupe : 030
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <stddef.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>



#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static int install_filter(int syscall_nr){ //Fonction extrait du man de seccomp

        //Seule l'architecture AUDIT_ARCH_X86_64 est autorisée
        int t_arch = AUDIT_ARCH_X86_64;
        

        struct sock_filter filter[] = {
            
            
            /* On charge l'architecture dans le "accumulator" */
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS,(offsetof(struct seccomp_data, arch))),
            
            /* Si c'est AUDIT_ARCH_X86_64 on saute de 1*/
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_arch, 1, 0),
            
            /* Architecture non autorisée : kill process. */
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            
            /* Architercture autorisée et on charge nr dans le "accumulator" */
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS,(offsetof(struct seccomp_data, nr))),
            
            /* On saute de 1 si la commande est est la même que "syscall_nr". */
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1),
            
            
            /* Commande interdite: kill process. */
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            
            /* L'appel système est autorisé */
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            
        };

        struct sock_fprog prog = {
            .len = ARRAY_SIZE(filter),
            .filter = filter,
        };
        int retour_1 = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
        if(retour_1 < 0)
            return 1;
    
        
        return 0;
    }


int main(int argc, char **argv){
    
    pid_t pid = fork(); //Création du processus fils
    
    if (pid<0)
        return 1; //La création du processus fils a échoué
        
    else if (pid == 0 ){ //Processus fils
        
        //Protection contre l'élévation de privilèges
        
        int retour2 = prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
        if (retour2 < 0)
            return 1;
        
        //Extraction des numéros des appels système à interdire et Installation des filtres
        
        char *tmp;
        tmp=strtok(argv[1],",");//On assume que les arguments sont valides
        
        while(tmp!=NULL){
            int retour3 = install_filter(atoi(tmp));
            if (retour3 == 1)
                return 1;//La fonction install_filter a échoué
            tmp= strtok(NULL, ",");
        }
        
        //Lancement de la commande
        
        int retour4 = execve(argv[2],argv+2,NULL);
        if (retour4 < 0)
            return 1;
    } 
    else{ //Processus parent
        
        
        //Attendre la fin du processus fils.
        int etat;
        int retour5 = waitpid(pid,&etat,WCONTINUED);
        if (retour5 < 0)
            return 1; // L'appel waitpid a échoué
        
        //Le fils s'est terminé normalment
        if (WIFEXITED(etat) == 1){
            
            printf("%d\n", WEXITSTATUS(etat));
            return 0;
        }
        
        //Le fils s'est termine à cause d'un signal reçu
        if (WIFSIGNALED(etat) == 1){
            
            printf("%d\n", WTERMSIG(etat));
            return 1;
        }
        //Autres cas
        return 0;
    }
    return 0;
}
