#include<stdio.h>
#include<math.h>
#include<time.h>
#include<string.h>
#include <stdlib.h>

// 計算フレーム(s)
#define st 0.001

//シミュレーション時間
#define TIME 14.0

//時定数
#define tau 0.1

//PD制御器ゲイン
#define ksp_p 0.2
#define ksp_d 0.7

// 通信遅延(ms)
#define sita_dff 10
#define sita_dfb 20

// 遅延モデル(ms)
#define dff_model 10
#define dfb_model 20

// アクチュエータ遅延(ms)
#define sita_a 10

// standstill distance(m)
#define r 2.5

// 前方車との時間差(s)
#define hsp 0.05

// e_mのカットオフ周波数
#define g_em 500



// 0号車を含む車の台数(台)
#define carNum 5

// SPを使うか否か（1で使用、0で不使用）
#define on_SP 1

//検出器しきい値
#define vth 0

//パス本数
#define pathNum 1
#define pathNum_fb 3

//正弦波攻撃
#define attack_AA 5
#define attack_w1 100
#define e_attack_AA 1
#define e_attack_w1 100


//推定器しきい値
#define u_th 1
//モデル化誤差
#define tau_er 1.00
//aging factor
#define alpha 0.01


// 所望加速度(m/s^2)
double u_AA[carNum];
//1サンプリング前所望加速度
double u_old_AA[carNum];
//微分所望加速度
double d_u_AA[carNum];
//遅延所望加速度
double u_ff_delay_AA[carNum];
//1サンプリング前遅延所望加速度
double u_ff_delay_old_AA[carNum];

//遅延予測した所望加速度(m/s^2)_AA[SPに用いる]
double u_pred_AA[carNum];
//フィードフォワード
double u_pred_ff_delay_AA[carNum][dff_model+1];

//現状の加速度(m/s^2)
double a_AA[carNum];
double a_old_AA[carNum];
double u_actu_delay_AA[carNum][sita_a+1];

//遅延なしと捉えた理想現状加速度(m/s^2)_AA[SPに用いる]
double a_ideal_AA[carNum];
double a_ideal_old_AA[carNum];
double u_ideal_actu_delay_AA[carNum][sita_a+1];

//遅延予測した現状加速度(m/s^2)_AA[SPに用いる]
double a_pred_AA[carNum];
double a_pred_old_AA[carNum];
double u_pred_actu_delay_AA[carNum][sita_a+1];

// 速度(m/s)
double v_AA[carNum];

//遅延なしと捉えた理想速度(m/s)_AA[SPに用いる]
double v_ideal_AA[carNum];

//遅延予測した速度(m/s)_AA[SPに用いる]
double v_pred_AA[carNum];
double v_pred_old_AA[carNum];
double d_v_pred_AA[carNum];

//現在位置(m)
double q_AA[carNum];
double q_old_AA[carNum];


//遅延なしと捉えた位置(m)_AA[SPに用いる]
double q_ideal_AA[carNum];
double q_ideal_old_AA[carNum][dff_model+1];

//遅延予測した位置(m)_AA[SPに用いる]
double q_pred_AA[carNum];
double q_pred_old_AA[carNum];

// 想定距離(m)
double dr_AA[carNum];

// 実際の距離(m)
double d_AA[carNum];

// 想定距離と実際の距離との誤差(m)
double e_AA[carNum];
double e_fb_delay_AA[carNum];

// 遅延なしと捉えた想定距離と実際の距離との誤差(m)_AA[SPに用いる]
double e_ideal_AA[carNum];
double e_ideal_fb_delay_AA[carNum][dfb_model+1];

// 遅延予測した想定距離と実際の距離との誤差(m)_AA[SPに用いる]
double e_pred_AA[carNum];
double e_pred_fb_delay_AA[carNum][dfb_model+1];

//遅延保証した距離誤差
double e_mixed_AA[carNum];
double d_e_mixed_AA[carNum];
double e_mixed_old_AA[carNum];
// e_mの疑似微分に用いる
double e_m_int_AA[carNum];

//PD制御器
double kusai_AA[carNum];


//パスごとの往路遅延
int delay[carNum][pathNum];

//往路パス遅延含む
double u_ff_path_delay[carNum][pathNum][sita_dff+1];
//往路パス
double u_path[carNum][pathNum];
//往路バッファリング
double u_bf[carNum][pathNum][sita_dff+1];
//遅延を考慮した同時の値
double u_sametime[carNum][pathNum];

//パスごとの復路遅延
int delay_fb[carNum][pathNum_fb];
//復路パス遅延Diff含む
double e_fb_path_delay[carNum][pathNum_fb][sita_dfb+1];
//復路パス
double e_fb_path[carNum][pathNum_fb];
//復路路バッファリング
double e_fb_bf[carNum][pathNum_fb][sita_dfb+1];
//遅延を考慮した同時の値
double e_fb_sametime[carNum][pathNum_fb];
//一周期前の車間距離誤差
double e_fb_delay_old_AA[carNum];


//値が通信されたかの確認
int K[carNum][pathNum][sita_dff+1];
int K_fb[carNum][pathNum_fb][sita_dff+1];
int K_bf[carNum][pathNum][sita_dfb+1];
int K_bf_fb[carNum][pathNum_fb][sita_dfb+1];
int recieve;
int recieve_fb;

//所望加速度差分
double Diff[carNum][pathNum-1];

//攻撃確認
double tamper=0;
int dcnt=0;

//差分最小値
int FALSE;
int TRUE;

//パス判断本数
int detect=(pathNum+1)/2;
int detect_fb=(pathNum_fb+1)/2;

//最大遅延フィードバック
double dff_fb[carNum][dfb_model+1];


//推定器
double u_ff_delay_est[carNum][dff_model+1];
double u_actu_delay_est[carNum][sita_a+1];
double a_est[carNum];
double a_old_est[carNum];
double v_est[carNum];
double q_est[carNum];
double d_est[carNum];
double dr_est[carNum];
double e_est[carNum];
double e_fb_delay_est[carNum][dfb_model+1];
double diff_est[carNum];
double diff_est_old[carNum];
double tmp[carNum];
double e_th[carNum];

//信頼度チェック
double re[carNum][pathNum_fb];
double e_rate[carNum][pathNum_fb];
double re_ave[carNum][pathNum_fb];
double re_ave_old[carNum][pathNum_fb];
double re_check[carNum][pathNum_fb];
double re_sum[carNum][pathNum_fb];
double e_no[carNum][pathNum_fb];
double no=0.0;
double re_sum_old[carNum];
double re_sum_sup[carNum][7];
//path1,2,3,12,23,13,123

// 扱うファイル
FILE *fp_a_AA;
FILE *fp_v_AA;
FILE *fp_d_AA;
FILE *fp_e_AA;
FILE *fp_q_AA;
FILE *fp_e_d_AA;
FILE *fp_e_p_A;
FILE *fp_e_m_AA;
FILE *fp_u_AA;
FILE *fp_u_d_AA;
FILE *fp_u_p_AA;
FILE *fp_u_path;
FILE *fp_u_bf;
FILE *fp_u_same;
FILE *fp_diff;
FILE *fp_est;
FILE *fp_e_er;
FILE *fp_e_rate;
FILE *fp_re;
FILE *fp_re_ave;
FILE *fp_re_check;
FILE *fp_re_sum;
FILE *fp_e_no;
FILE *fp_re_sum_sup;
/***************
共通項目
*****************/
// 所望加速度及び速度
double des_v,des_a;

// 経過時間(s)
double t = 0.0;

// 経過時間(s)
double cPoint[9];





// 初期化
void Init(void){
  cPoint[0]=0.0;
  cPoint[1]=cPoint[0]+1.0;
  cPoint[2]=cPoint[1]+1.0;
  cPoint[3]=cPoint[2]+1.0;
  cPoint[4]=cPoint[3]+5.0;
  cPoint[5]=cPoint[4]+1.0;
  cPoint[6]=cPoint[5]+1.0;
  cPoint[7]=cPoint[6]+1.0;
  cPoint[8]=cPoint[7]+3.0;
  des_v=0;
  des_a=0;

}

// 配列の初期化
void Init_Array_AA(void){
  int i ,j,n,l;
  
  for(i=0;i<carNum;i++){

    for(n=0;n<pathNum;n++){
    delay[i][n]=0;
    
    u_path[i][n]=0;
    
    u_sametime[i][n]=0;
    
    }
    for(n=0;n<pathNum_fb;n++){
    
    delay_fb[i][n]=0;
    
    e_fb_path[i][n]=0;
    
    e_fb_sametime[i][n]=0;
    }
    for(n=0;n<pathNum-1;n++){
      Diff[i][n]=0;
    }
        

    u_ff_delay_AA[i]=0;
    u_ff_delay_old_AA[i]=0;
    e_fb_delay_old_AA[i]=0;

    // 実際の被制御
    u_AA[i]=0;
    d_u_AA[i]=0;
    u_old_AA[i]=0;

    a_AA[i]=0;
    a_old_AA[i]=0;

    v_AA[i]=0;

    q_AA[i]=0;
    q_old_AA[i]=0;

    e_AA[i]=0;

    e_mixed_AA[i]=0;
    d_e_mixed_AA[i]=0;
    e_mixed_old_AA[i]=0;
    e_m_int_AA[i]=0;

    dr_AA[i]=0;
    d_AA[i]=0;
    e_fb_delay_AA[i]=0;
    
    for(j=0;j<sita_a+1;j++){
      u_actu_delay_AA[i][j]=0;
    }

    for(n=0;n<pathNum;n++){
      for(j=0;j<sita_dff+1;j++){
        u_ff_path_delay[i][n][j]=0;
        u_bf[i][n][j]=0;
      }
      for(l=0;l<sita_dfb+1;l++){
        e_fb_path_delay[i][n][l]=0;
        e_fb_bf[i][n][l]=0;
      }
    }
    for(n=0;n<pathNum;n++){
      for(j=0;j<sita_dff+1;j++){
        K[i][n][j]=0;
        K_bf[i][n][j]=0;
        

      }
  
    }
    for(n=0;n<pathNum_fb;n++){
      for(j=0;j<sita_dfb+1;j++){

        K_fb[i][n][j]=0;
        K_bf_fb[i][n][j]=0;

      }
  
    }
    recieve=0;
    recieve_fb=0;

// 遅延なしの被制御

    a_ideal_AA[i]=0;
    a_ideal_old_AA[i]=0;

    v_ideal_AA[i]=0;

    q_ideal_AA[i]=0;

    e_ideal_AA[i]=0;

    for(j=0;j<sita_a+1;j++){
      u_ideal_actu_delay_AA[i][j]=0;
    }
    for(j=0;j<dfb_model+1;j++){
      e_ideal_fb_delay_AA[i][j]=0;
      dff_fb[i][j]=0;
    }

// 遅延予測の被制御
    u_pred_AA[i]=0;

    a_pred_AA[i]=0;
    a_pred_old_AA[i]=0;

    v_pred_AA[i]=0;
    d_v_pred_AA[i]=0;
    v_pred_old_AA[i]=0;

    q_pred_AA[i]=0;

    e_pred_AA[i]=0;
    for(j=0;j<sita_a+1;j++){
      u_pred_actu_delay_AA[i][j]=0;
    }
    for(j=0;j<dff_model+1;j++){
      u_pred_ff_delay_AA[i][j]=0;
    }
    for(j=0;j<dfb_model+1;j++){
      e_pred_fb_delay_AA[i][j]=0;
    }


      a_est[i]=0;
      a_old_est[i]=0;
      v_est[i]=0;
      d_est[i]=0;
      dr_est[i]=0;
      e_est[i]=0;
    for(j=0;j<dff_model+1;j++){
      u_ff_delay_est[i][j]=0;
    }
    for(j=0;j<sita_a+1;j++){
      u_actu_delay_est[i][j]=0;
    }
     diff_est[i]=0;
     diff_est_old[i]=0;
     tmp[i]=0;
     e_th[i]=0;
    for(j=0;j<dfb_model+1;j++){
      e_fb_delay_est[i][j];
    }
   //信頼値
   for(j=0;j<pathNum_fb;j++){
   re[i][j]=0;
   e_rate[i][j]=0;
   re_ave[i][j]=0;
   re_ave_old[i][j]=1;
   re_sum[i][j]=0;
   e_no[i][j]=0;
   
   }
   for(j=0;j<7;j++){
   re_sum_sup[i][j]=0;
   }
   
   re_sum_old[i]=0;



  }

// 車の初期位置の決定
  q_AA[0]=carNum*r;
  q_ideal_AA[0]=q_AA[0];
  q_pred_AA[0]=q_AA[0];
  q_old_AA[0]=q_AA[0];
  q_est[0]=q_AA[0];
  for(i=1;i<carNum;i++){
    q_AA[i]=q_AA[i-1]-r;
    q_ideal_AA[i]=q_AA[i];
    q_pred_AA[i]=q_AA[i];
    q_old_AA[i]=q_AA[i];
    q_est[i]=q_AA[i];
    for(j=0;j<dff_model+1;j++){
      q_ideal_old_AA[i][j]=q_AA[i];
      }
    }


    
}

// 0号車の所望加速度の変化
void imputAccr(void){
  if(cPoint[0]<=t&&t<cPoint[1]){
    d_u_AA[0] = 11.0*st;
  }
  else if(cPoint[1]<=t&&t<cPoint[2]){
    d_u_AA[0] = 0.0*st;
  }
  else if(cPoint[2]<=t&&t<cPoint[3]){
    d_u_AA[0] = -11.0*st;
  }
  else if(cPoint[3]<=t&&t<cPoint[4]){
    d_u_AA[0] = 0.0*st;
  }
  else if(cPoint[4]<=t&&t<cPoint[5]){
    d_u_AA[0] = -9.0*st;
  }
  else if(cPoint[5]<=t&&t<cPoint[6]){
    d_u_AA[0] = 0.0*st;
  }
  else if(cPoint[6]<=t&&t<cPoint[7]){
    d_u_AA[0] = 9.0*st;
  }
  else if(cPoint[7]<=t&&t<cPoint[8]){
    d_u_AA[0] = 0.0*st;
  }


  u_AA[0]+=d_u_AA[0];
}



int main(void){
  //ループ用の整数
  int i;
  int j;
  int n;
  int b=0;

  int y=0;
  int s=0;
  // 各種初期化
  Init();
  Init_Array_AA();

    // 現在時刻から乱数生成
  srand((unsigned int)time(NULL));

// ファイル取得
{
  fp_a_AA = fopen("sp_data_a.dat","w");
  fp_v_AA = fopen("sp_data_v.dat","w");
  fp_q_AA = fopen("sp_data_q.dat","w");
  fp_d_AA = fopen("sp_data_d.dat","w");
  fp_e_AA = fopen("sp_data_e.dat","w");
  fp_e_p_A = fopen("sp_data_e_p.dat","w");
  fp_e_d_AA = fopen("sp_data_e_d.dat","w");
  fp_e_m_AA = fopen("sp_data_e_m.dat","w");
  fp_u_AA = fopen("sp_data_u.dat","w");
  fp_u_p_AA = fopen("sp_data_u_p.dat","w");
  fp_u_d_AA = fopen("sp_data_u_d.dat","w");
  fp_u_path=fopen("sp_data_u_path.dat","w");
  fp_u_bf=fopen("sp_data_u_bf.dat","w");
  fp_u_same=fopen("sp_data_u_same.dat","w");
  fp_diff=fopen("sp_data_diff.dat","w");
  fp_est=fopen("sp_data_est.dat","w");
  fp_e_er=fopen("sp_data_e_er.dat","w");
  fp_e_rate=fopen("sp_data_e_rate.dat","w");
  fp_re=fopen("sp_data_re.dat","w");
  fp_re_ave=fopen("sp_data_re_ave.dat","w");
  fp_re_check=fopen("sp_data_re_check.dat","w");
  fp_re_sum=fopen("sp_data_re_sum.dat","w");
  fp_e_no=fopen("sp_data_e_no.dat","w");
  fp_re_sum_sup=fopen("sp_data_re_sum_sup.dat","w");
  
}
  
  while(t<=TIME){

    //パスごとの遅延
    for(i=0;i<carNum;i++){
     delay[i][0]=10;
     delay[i][1]=15;
     delay[i][2]=20;
     delay[i][3]=25;
     delay[i][4]=30;
     delay[i][5]=35;
     delay[i][6]=40;
     delay_fb[i][0]=10;
     delay_fb[i][1]=15;
     delay_fb[i][2]=20;
     delay_fb[i][3]=25;
     delay_fb[i][4]=30;
     delay_fb[i][5]=35;
     delay_fb[i][6]=40;
    }







    /*******************************************************************
     　　　　　　　　　　　　自動運転システム
    ***********************************************************************/
   {//収納用のカッコ
    // 0号車の処理を行う

    // 0号車の所望加速度の変化
    imputAccr();
    // imputAccr_2();
    // imputAccrSimple();
      
    // アクチュエータ遅延
    memmove(&u_actu_delay_AA[0][1], u_actu_delay_AA[0], sizeof(double[sita_a]));
    u_actu_delay_AA[0][0]=u_AA[0];
    // 加速度の計算
    a_AA[0]+=st*(u_actu_delay_AA[0][sita_a]-a_old_AA[0])/tau;
    a_old_AA[0]=a_AA[0];
    // 速度の計算
    v_AA[0]+=st*a_AA[0];
    // 位置の計算
    q_AA[0]+=v_AA[0]*st;

    //1号車～(carNum-1)号車まで同様の処理を行う
    for(i=1;i<carNum;i++){

        /***************           (i-1)号車による制御           ****************/
            //情報損失
      /*Communication_fb_Loss_AA(i);*/ 
      e_mixed_AA[i]=e_fb_delay_AA[i]-(e_pred_fb_delay_AA[i][dfb_model]-e_ideal_fb_delay_AA[i][dfb_model])*on_SP;

      d_e_mixed_AA[i]=(e_mixed_AA[i]-e_m_int_AA[i])*g_em;
      e_m_int_AA[i]=e_m_int_AA[i]+d_e_mixed_AA[i]*st;
      e_mixed_old_AA[i]=e_mixed_AA[i];
      // PD制御器の計算
        if(i==1){
        kusai_AA[i]=u_AA[0]+ksp_p*e_mixed_AA[i]+ksp_d*d_e_mixed_AA[i];
        }else{
        kusai_AA[i]=u_ff_delay_AA[i-1]+ksp_p*e_mixed_AA[i]+ksp_d*d_e_mixed_AA[i];
        }

      // 所望加速度の計算
      u_AA[i]+=st*(kusai_AA[i]-u_old_AA[i])/hsp;
      u_old_AA[i]=u_AA[i];


    //ff遅延
    for(n=0;n<pathNum;n++){
      u_path[i][n]=u_AA[i];
    }
    /*if(0.0<=t&&t<3.0){
      u_path[1][1]=-10;
      u_path[2][1]=-10;
      u_path[3][1]=-10;
      u_path[4][1]=-10;
      }*/
    if(8.0<=t&&t<11.0){
      //u_path[i][0]-=attack_AA*sin(attack_w1*t);
      //u_path[i][1]-=attack_AA*sin(attack_w1*t);
      }
      if(0.0<=t&&t<3.0){
      //u_path[i][0]+=attack_AA*sin(attack_w1*t);
      //u_path[i][1]+=attack_AA*sin(attack_w1*t);
      //u_path[3][0]+=attack_AA*sin(attack_w1*t);
      }
     
    
    //パス遅延
    for(n=0;n<pathNum;n++){
      memmove(&u_ff_path_delay[i][n][1],u_ff_path_delay[i][n],sizeof(double[sita_dff]));
      u_ff_path_delay[i][n][0]=u_path[i][n];}
    for(n=0;n<pathNum;n++){
      memmove(&u_bf[i][n][1],u_bf[i][n],sizeof(double[sita_dff]));
      u_bf[i][n][0]=u_ff_path_delay[i][n][delay[i][n]];
    }
    int p;
    //遅延を小さい順に
    for(p=0;p<pathNum-1;p++){
    for(n=pathNum-1;n>p;n--){
        if(delay[n-1]>delay[n]){
          double x=u_bf[i][n-1][0];
          u_bf[i][n-1][0]=u_bf[i][n][0];
          u_bf[i][n][0]=x;
          double l=delay[i][n-1];
          delay[i][n-1]=delay[i][n];
          delay[i][n]=l; 
        }
    }  

    }



    for(n=0;n<pathNum;n++){
      u_sametime[i][n]=u_bf[i][n][sita_dff-delay[i][n]];
    }
    int m;
    for(m=0;m<pathNum;m++){
        memmove(&K[i][m][1],K[i][m],sizeof(int[sita_dff]));
        K[i][m][0]=1;
      /* if(15.0<=t&&t<20.0){
        K[i][0][0]=0;
      }
       if(45.0<=t&&t<50.0){
        K[i][0][0]=0;
        K[i][1][0]=0;
      }
       if(70.0<=t&&t<80.0){
        K[i][0][0]=0;
        K[i][1][0]=0;
        K[i][2][0]=0;
      }*/
        memmove(&K_bf[i][m][1],K_bf[i][m],sizeof(int[sita_dff]));
        K_bf[i][m][0]=K[i][m][delay[i][m]];
}

recieve=0;
  int count;
  int E[carNum][pathNum];
  int qqq;
  for(m=0;m<pathNum;m++){
        
    if(K_bf[i][m][sita_dff-delay[i][m]]==1){
      recieve+=1;
      E[i][m]=0;
    }
    else{
      E[i][m]=1;
    }
    }
  
  if(recieve==pathNum){
    for(j=0;j<pathNum;j++){
      dcnt=0;
      for(n=0;n<pathNum;n++){
        if(fabs(u_sametime[i][n]-u_sametime[i][j])>vth){
          dcnt+=1;
        }
      }
      if(dcnt<detect){
        u_ff_delay_AA[i]=u_sametime[i][j];
        y=j;
          break;
      }
    
      else{
        u_ff_delay_AA[i]=u_ff_delay_old_AA[i];
      }
    }}
  
  else{
    u_ff_delay_AA[i]=u_ff_delay_old_AA[i];
  }

          u_ff_delay_old_AA[i]=u_ff_delay_AA[i];


  

    /********スミス予測器＿＿理想制御器の部******/
    //アクチュエータ遅延
      memmove(&u_ideal_actu_delay_AA[i][1], u_ideal_actu_delay_AA[i], sizeof(double[sita_a]));
      u_ideal_actu_delay_AA[i][0]=u_AA[i];
      // 加速度の計算
      a_ideal_AA[i]+=st*(u_ideal_actu_delay_AA[i][sita_a]-a_ideal_old_AA[i])/tau;
      a_ideal_old_AA[i]=a_ideal_AA[i];
            //速度の計算
      v_ideal_AA[i]=v_ideal_AA[i]+st*a_ideal_AA[i];
      // 位置の計算
      q_ideal_AA[i]=q_ideal_AA[i]+st*v_ideal_AA[i];
      // 前方車の実際の距離の誤差
      e_ideal_AA[i]=q_AA[i-1]-(q_ideal_AA[i]+r+hsp*v_ideal_AA[i]);
      //fb遅延
      memmove(&e_ideal_fb_delay_AA[i][1], e_ideal_fb_delay_AA[i], sizeof(double[dfb_model]));
      e_ideal_fb_delay_AA[i][0]=e_ideal_AA[i];

    /*******スミス予測器＿＿遅延保障の部*********/

    //予測ff遅延
      memmove(&u_pred_ff_delay_AA[i][1], u_pred_ff_delay_AA[i], sizeof(double[dff_model]));
      u_pred_ff_delay_AA[i][0]=u_AA[i];
    //アクチュエータ遅延
      memmove(&u_pred_actu_delay_AA[i][1], u_pred_actu_delay_AA[i], sizeof(double[sita_a]));
      u_pred_actu_delay_AA[i][0]=u_pred_ff_delay_AA[i][sita_dff];
      // 加速度の計算
      a_pred_AA[i]+=st*(u_pred_actu_delay_AA[i][sita_a]-a_pred_old_AA[i])/tau;
      a_pred_old_AA[i]=a_pred_AA[i];
      //速度の計算
      v_pred_AA[i]+=st*a_pred_AA[i];
      // 位置の計算
      q_pred_AA[i]+=st*v_pred_AA[i];
      // 前方車の実際の距離の誤差 
      e_pred_AA[i]=q_AA[i-1]-(q_pred_AA[i]+r+hsp*v_pred_AA[i]);
      //fb遅延
      memmove(&e_pred_fb_delay_AA[i][1], e_pred_fb_delay_AA[i], sizeof(double[dfb_model]));
      e_pred_fb_delay_AA[i][0]=e_pred_AA[i];



      /*******推定器***********/
      //遅延モデル
      memmove(&u_ff_delay_est[i][1],u_ff_delay_est[i],sizeof(double[dff_model]));
      u_ff_delay_est[i][0]=u_AA[i];
      // アクチュエータ遅延
      memmove(&u_actu_delay_est[i][1], u_actu_delay_est[i], sizeof(double[sita_a]));
      u_actu_delay_est[i][0]=u_ff_delay_est[i][dff_model];
      // 加速度の計算
      a_est[i]+=st*(u_actu_delay_est[i][sita_a]-a_old_est[i])/(tau*tau_er);
      a_old_est[i]=a_est[i];
      //速度の計算
      v_est[i]+=st*a_est[i];
      // 位置の計算
      q_est[i]+=st*v_est[i];
      if(q_est[i]>q_AA[i-1]){
        q_est[i]=q_AA[i-1];
      }
      // 前方車の実際の距離の計算
      d_est[i]=q_AA[i-1]-q_est[i];
      // 前方車との想定の距離
      dr_est[i]=r+hsp*v_est[i];
      // 想定と実際の前方車との距離の誤差
      e_est[i]=d_est[i]-dr_est[i];
      memmove(&e_fb_delay_est[i][1],e_fb_delay_est[i],sizeof(double[dfb_model]));
      e_fb_delay_est[i][0]=e_est[i];






          /***************           i号車による被制御           ****************/

      // アクチュエータ遅延
      memmove(&u_actu_delay_AA[i][1], u_actu_delay_AA[i], sizeof(double[sita_a]));
      u_actu_delay_AA[i][0]=u_ff_delay_AA[i];
      // 加速度の計算
      a_AA[i]+=st*(u_actu_delay_AA[i][sita_a]-a_old_AA[i])/tau;
      a_old_AA[i]=a_AA[i];
      //速度の計算
      v_AA[i]+=st*a_AA[i];
      // 位置の計算
      q_AA[i]+=st*v_AA[i];
      if(q_AA[i]>q_AA[i-1]){
        q_AA[i]=q_AA[i-1];
      }
      // 前方車の実際の距離の計算
      d_AA[i]=q_AA[i-1]-q_AA[i];
      // 前方車との想定の距離
      dr_AA[i]=r+hsp*v_AA[i];
      // 想定と実際の前方車との距離の誤差
      e_AA[i]=d_AA[i]-dr_AA[i];

      //fb遅延
      for(n=0;n<pathNum_fb;n++){
      e_fb_path[i][n]=e_AA[i];

      }
      if(0.0<=t&&t<3.0){
       /*e_fb_path[1][0]+=attack_AA*sin(attack_w1*t);
        e_fb_path[2][0]+=attack_AA*sin(attack_w1*t);
        e_fb_path[3][0]+=attack_AA*sin(attack_w1*t);
        e_fb_path[4][0]+=attack_AA*sin(attack_w1*t);
        e_fb_path[1][1]+=attack_AA*sin(attack_w1*t);
        e_fb_path[2][1]+=attack_AA*sin(attack_w1*t);
        e_fb_path[3][1]+=attack_AA*sin(attack_w1*t);
        e_fb_path[4][1]+=attack_AA*sin(attack_w1*t);
        e_fb_path[1][2]+=attack_AA*sin(attack_w1*t);
        e_fb_path[2][2]+=attack_AA*sin(attack_w1*t);
        e_fb_path[3][2]+=attack_AA*sin(attack_w1*t);
        e_fb_path[4][2]+=attack_AA*sin(attack_w1*t);*/
     }
      
      if(8.0<=t&&t<11.0){
        e_fb_path[i][0]-=e_attack_AA*sin(e_attack_w1*t);
        e_fb_path[i][1]-=e_attack_AA*sin(e_attack_w1*t);
        //e_fb_path[i][2]-=e_attack_AA*sin(e_attack_w1*t);
        //e_fb_path[i][0]=10;
        //e_fb_path[i][1]=10;
        //e_fb_path[i][2]=10;
      }
      if(0.0<=t&&t<3.0){
        /*e_fb_path[1][0]=10;
        e_fb_path[2][0]=10;
        e_fb_path[3][0]=10;
        e_fb_path[4][0]=10;
        e_fb_path[1][1]=10;
        e_fb_path[2][1]=10;
        e_fb_path[3][1]=10;
        e_fb_path[4][1]=10;*/
      }

      
      for(n=0;n<pathNum_fb;n++){
      memmove(&e_fb_path_delay[i][n][1],e_fb_path_delay[i][n],sizeof(double[sita_dfb]));
      e_fb_path_delay[i][n][0]=e_fb_path[i][n];
      }
      //fbパス遅延
      for(n=0;n<pathNum_fb;n++){
      memmove(&e_fb_bf[i][n][1],e_fb_bf[i][n],sizeof(double[sita_dfb]));
      e_fb_bf[i][n][0]=e_fb_path_delay[i][n][delay_fb[i][n]];
     }
  
     //fb遅延を小さい順に
     for(p=0;p<pathNum_fb-1;p++){
     for(n=pathNum_fb-1;n>p;n--){
         if(delay_fb[n-1]>delay_fb[n]){
           double g=e_fb_bf[i][n-1][0];
           e_fb_bf[i][n-1][0]=e_fb_bf[i][n][0];
           e_fb_bf[i][n][0]=g;
           double f=delay_fb[i][n-1];
           delay_fb[i][n-1]=delay_fb[i][n];
           delay_fb[i][n]=f; 
        }
    }  
    }

     for(n=0;n<pathNum_fb;n++){
      e_fb_sametime[i][n]=e_fb_bf[i][n][sita_dfb-delay_fb[i][n]];
    }
for(m=0;m<pathNum_fb;m++){
        memmove(&K_fb[i][m][1],K_fb[i][m],sizeof(int[sita_dfb]));
        K_fb[i][m][0]=1;
        memmove(&K_bf_fb[i][m][1],K_bf_fb[i][m],sizeof(int[sita_dfb]));
        K_bf_fb[i][m][0]=K_fb[i][m][delay_fb[i][m]];
}
recieve_fb=0;
  for(m=0;m<pathNum_fb;m++){
        
    if(K_bf_fb[i][m][sita_dfb-delay_fb[i][m]]==1){
      recieve_fb+=1;
    }
    }
  
 /*if(recieve_fb==pathNum_fb){
    for(j=0;j<pathNum;j++){
      dcnt=0;
      for(n=0;n<pathNum_fb;n++){
        if(fabs(e_fb_sametime[i][n]-e_fb_sametime[i][j])>vth){
          dcnt+=1;
        }
      }
      if(dcnt<detect){
        e_fb_delay_AA[i]=e_fb_sametime[i][j];
        s=j;
          break;
      }
    
      else{
        e_fb_delay_AA[i]=e_fb_delay_old_AA[i];
      }
    }
  }
  else{
    e_fb_delay_AA[i]=e_fb_delay_old_AA[i];
  }*/


tmp[i]=0;
//e_th[i]=e_fb_delay_est[i][dfb_model]*u_th;
diff_est_old[i]=fabs(e_fb_sametime[i][0]-e_fb_delay_est[i][dfb_model]);
e_fb_delay_AA[i]=e_fb_sametime[i][0];
s=0;

//信頼度チェック
for(m=0;m<pathNum_fb;m++){
  if(e_fb_sametime[i][m]==0 && e_fb_delay_est[i][dfb_model]==0){
    re[i][m]=0.0;
    e_rate[i][m]=0.0;
  }
  else{
  e_rate[i][m]=fabs((e_fb_sametime[i][m]-e_fb_delay_est[i][dfb_model])/e_fb_delay_est[i][dfb_model]);
  }
}
//信頼値計算_ver1
/*for(m=0;m<pathNum_fb;m++){
if(e_rate[i][m]<=0.1){
  re[i][m]=1.0;
}
else if(0.1<e_rate[i][m]<=0.3){
  re[i][m]=0.5;
}
else{
  re[i][m]=0.0;
}
}*/

//信頼値計算_ver2
double f;
for(m=0;m<pathNum_fb;m++){
e_no[i][m]=0.0;
}
for(m=0;m<pathNum_fb;m++){
  for(j=0;j<pathNum_fb;j++){
   if(e_rate[i][m]>e_rate[i][j]){
           e_no[i][m]+=1;
   }
   else{
           e_no[i][m]+=0;
   }
  }
}
for(m=0;m<pathNum_fb;m++){
  if(e_no[i][m]==0.0){
     re[i][m]=1.0;
  }
  if(e_no[i][m]==1.0){
     re[i][m]=0.45;
  }
  if(e_no[i][m]==2.0){
     re[i][m]=0.0;
  }  
}
//移動加重平均
for(m=0;m<pathNum_fb;m++){
   re_ave[i][m]=alpha*re[i][m]+(1-alpha)*re_ave_old[i][m];
   re_ave_old[i][m]=re_ave[i][m];
}
for(m=0;m<pathNum_fb;m++){
  re_check[i][m]=m;
}
//dataの分類
for(m=0;m<pathNum_fb;m++){
  for(j=0;j<pathNum_fb;j++){
  if(e_fb_sametime[i][m]==e_fb_sametime[i][j]){
    re_check[i][j]=m;
   }
  }
}
//信頼値の足し合わせ
for(m=0;m<pathNum_fb;m++){
re_sum[i][m]=0.0;
}
double o;
for(m=0;m<pathNum_fb;m++){
  for(j=m;j<pathNum_fb;j++){
   if(re_check[i][m]==re_check[i][j]){
    re_sum[i][m]+=re_ave[i][j];
   }
  }
}
//信頼値見やすいグラフ作成のため
re_sum_sup[i][m]=-1.0;
}
if(re_check[i][0]!=re_check[i][1] && re_check[i][1]!=re_check[i][2] && re_check[i][0]!=re_check[i][2]){
    re_sum_sup[i][0]=re_ave[i][0];
    re_sum_sup[i][1]=re_ave[i][1];
    re_sum_sup[i][2]=re_ave[i][2];
}
else if(re_check[i][0]==re_check[i][1] && re_check[i][0]!=re_check[i][2]){
    re_sum_sup[i][3]=re_ave[i][0]+re_ave[i][1];
    re_sum_sup[i][2]=re_ave[i][2];
}
else if(re_check[i][1]==re_check[i][2] && re_check[i][0]!=re_check[i][1]){
    re_sum_sup[i][4]=re_ave[i][1]+re_ave[i][2];
    re_sum_sup[i][0]=re_ave[i][0];
}
else if(re_check[i][0]==re_check[i][2] && re_check[i][0]!=re_check[i][1]){
    re_sum_sup[i][5]=re_ave[i][0]+re_ave[i][2];
    re_sum_sup[i][1]=re_ave[i][1];
}
else if(re_check[i][0]==re_check[i][1] && re_check[i][1]==re_check[i][2]){
    re_sum_sup[i][6]=re_ave[i][0]+re_ave[i][1]+re_ave[i][2];
}





re_sum_old[i]=re_sum[i][0];
if(recieve_fb==pathNum_fb){
for(m=1;m<pathNum_fb;m++){
  if(re_sum[i][m]>re_sum_old[i]){
   e_fb_delay_AA[i]=e_fb_sametime[i][m];
   re_sum_old[i]=re_sum[i][m];
   s=m;
  }
}
}
e_fb_delay_old_AA[i]=e_fb_delay_AA[i];




  //推定器による検知（一番推定に近いパスを入力に使用）
  /*if(recieve_fb==pathNum_fb){
  for(m=1;m<pathNum_fb;m++){
    diff_est[i]=fabs(e_fb_sametime[i][m]-e_fb_delay_est[i][dfb_model]);
    if(diff_est[i]<diff_est_old[i]){
        e_fb_delay_AA[i]=e_fb_sametime[i][m];
        diff_est_old[i]=diff_est[i];
        s=m;
        //b=m;
        
    }
  }
  }
    e_fb_delay_old_AA[i]=e_fb_delay_AA[i];*/

}
   //datファイルへの書き込み
    fprintf(fp_a_AA,"%lf\t",t);
    fprintf(fp_v_AA,"%lf\t",t);
    fprintf(fp_d_AA,"%lf\t",t);
    fprintf(fp_e_AA,"%lf\t",t);
    fprintf(fp_q_AA,"%lf\t",t);
    fprintf(fp_e_d_AA,"%lf\t",t);
    fprintf(fp_e_p_A,"%lf\t",t);
    fprintf(fp_e_m_AA,"%lf\t",t);
    fprintf(fp_u_AA,"%lf\t",t);
    fprintf(fp_u_p_AA,"%lf\t",t);
    fprintf(fp_u_d_AA,"%lf\t",t);
    fprintf(fp_u_path,"%lf\t",t);
    fprintf(fp_u_bf,"%lf\t",t);
    fprintf(fp_u_same,"%lf\t",t);
    fprintf(fp_diff,"%lf\t",t);
    fprintf(fp_est,"%lf\t",t);
    fprintf(fp_e_er,"%lf\t",t);
    fprintf(fp_e_rate,"%lf\t",t);
    fprintf(fp_re,"%lf\t",t);
    fprintf(fp_re_ave,"%lf\t",t);
    fprintf(fp_re_check,"%lf\t",t);
    fprintf(fp_re_sum,"%lf\t",t);
    fprintf(fp_e_no,"%lf\t",t);
    fprintf(fp_re_sum_sup,"%lf\t",t);
    for(j=0;j<carNum;j++){
        fprintf(fp_a_AA,"%lf\t",a_AA[j]);
        fprintf(fp_v_AA,"%lf\t",v_AA[j]);
        fprintf(fp_d_AA,"%lf\t",d_AA[j]);
        fprintf(fp_e_AA,"%lf\t",e_fb_delay_AA[j]);
        fprintf(fp_q_AA,"%lf\t",q_AA[j]);
        fprintf(fp_e_p_A,"%lf\t",e_fb_delay_est[j][dfb_model]);
        fprintf(fp_e_d_AA,"%lf\t",e_fb_sametime[j][0]);
        fprintf(fp_e_m_AA,"%lf\t",e_th[j]);
        fprintf(fp_u_AA,"%lf\t",u_AA[j]);
        fprintf(fp_est,"%lf\t",diff_est[j]);
        
    }
      fprintf(fp_e_er,"%lf\t",e_fb_delay_est[2][dfb_model]);

      for(i=0;i<pathNum_fb;i++){
          fprintf(fp_e_er,"%lf\t",e_fb_sametime[2][i]);
          
        }
for(j=0;j<pathNum;j++){
    fprintf(fp_u_d_AA,"%d\t",K[2][j][0]);
}

    //fprintf(fp_diff,"%d\t",y);
    //fprintf(fp_diff,"%d\t",s+6);
    fprintf(fp_diff,"%d\t",s);
    for(n=0;n<pathNum;n++){
        fprintf(fp_u_p_AA,"%lf\t",u_path[2][n]);
        fprintf(fp_u_same,"%lf\t",u_sametime[2][n]); 
        }
    for(j=0;j<pathNum_fb;j++){
    fprintf(fp_e_rate,"%lf\t",e_rate[2][j]);
    fprintf(fp_re,"%lf\t",re[2][j]);
    fprintf(fp_re_ave,"%lf\t",re_ave[2][j]);
    fprintf(fp_re_check,"%lf\t",re_check[2][j]);
    fprintf(fp_re_sum,"%lf\t",re_sum[2][j]);
    fprintf(fp_e_no,"%lf\t",e_no[2][j]);
}
    for(j=0;j<7;j++){
    fprintf(fp_re_sum_sup,"%lf\t",re_sum_sup[2][j]);
}

    
    fprintf(fp_a_AA,"\n");
    fprintf(fp_v_AA,"\n");
    fprintf(fp_d_AA,"\n");
    fprintf(fp_e_AA,"\n");
    fprintf(fp_q_AA,"\n");
    fprintf(fp_e_d_AA,"\n");
    fprintf(fp_e_p_A,"\n");
    fprintf(fp_e_m_AA,"\n");
    fprintf(fp_u_p_AA,"\n");
    fprintf(fp_u_d_AA,"\n");
    fprintf(fp_u_AA,"\n");
    fprintf(fp_u_path,"\n");
    fprintf(fp_u_bf,"\n");
    fprintf(fp_u_same,"\n");
    fprintf(fp_diff,"\n");
    fprintf(fp_est,"\n");
    fprintf(fp_e_er,"\n");
    fprintf(fp_e_rate,"\n");
    fprintf(fp_re,"\n");
    fprintf(fp_re_ave,"\n");
    fprintf(fp_re_check,"\n");
    fprintf(fp_re_sum,"\n");
    fprintf(fp_e_no,"\n");
    fprintf(fp_re_sum_sup,"\n");
  }//収納用のカッコ

    
    t += st;
  
  }  
   fclose(fp_a_AA);
   fclose(fp_v_AA);
   fclose(fp_d_AA);
   fclose(fp_e_AA);
   fclose(fp_q_AA);
   fclose(fp_e_d_AA);
   fclose(fp_e_m_AA);
   fclose(fp_e_p_A);
   fclose(fp_u_p_AA);
   fclose(fp_u_d_AA);
   fclose(fp_u_AA);
   fclose(fp_u_path);
   fclose(fp_u_bf);
   fclose(fp_u_same);
   fclose(fp_diff);
   fclose(fp_est);
   fclose(fp_e_er);
   fclose(fp_e_rate);
   fclose(fp_re);
   fclose(fp_re_ave);
   fclose(fp_re_check);
   fclose(fp_re_sum);
   fclose(fp_e_no);
   fclose(fp_re_sum_sup);
   
    return(0);

}
