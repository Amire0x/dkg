use crate::dkg::dkg::{
    Keys, Parameters,
     SharedKeys,
};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Bls12_381_1, Point, Scalar};
use curv::BigInt;

fn keygen_t_n_parties(
    t: u16,
    n: u16,
) -> (
    Vec<Keys>,
    Vec<SharedKeys>,
    Vec<Point<Bls12_381_1>>,
    Point<Bls12_381_1>,
    VerifiableSS<Bls12_381_1>,
) {
    let parames = Parameters {
        threshold: t,
        share_count: n,
    };
    //初始化
    let party_keys_vec = (0..n).map(Keys::create).collect::<Vec<Keys>>();

    //第一阶段广播信息，承诺，同态公钥等等
    let (bc1_vec, decom_vec): (Vec<_>, Vec<_>) = party_keys_vec
        .iter()
        .map(|k| k.phase1_broadcast())
        .unzip();

    //计算g*ui之和得到g*X作为公钥
    let y_vec = (0..usize::from(n))
        .map(|i| decom_vec[i].y_i.clone())
        .collect::<Vec<Point<Bls12_381_1>>>();
    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);
    //g*ui承诺验证和生成feldmanvss的秘密分享
    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();

    let vss_result: Vec<_> = party_keys_vec
        .iter()
        .map(|k| {
            k.phase1_verify_com_phase2_vss_distribute(
                &parames, &decom_vec, &bc1_vec,
            )
            .expect("invalid key")
        })
        .collect();

    for (vss_scheme, secret_shares, index) in vss_result {
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares); // cannot unzip
        index_vec.push(index as u16);
    }

    let vss_scheme_for_test = vss_scheme_vec.clone();
    //收集每个用户的收到的f(i)集合
    let party_shares = (0..usize::from(n))
        .map(|i| {
            (0..usize::from(n))
                .map(|j| secret_shares_vec[j][i].clone())
                .collect::<Vec<Scalar<Bls12_381_1>>>()
        })
        .collect::<Vec<Vec<Scalar<Bls12_381_1>>>>();

    //验证share，生成对xi的承诺
    let mut shared_keys_vec = Vec::new();
    let mut dlog_proof_vec = Vec::new();
    for (i, key) in party_keys_vec.iter().enumerate() {
        let (shared_keys, dlog_proof) = key
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(//对share值进行验证，然后求和生成xi以及xi的零知识证明，返回y^ui求和
                &parames,
                &y_vec,
                &party_shares[i],
                &vss_scheme_vec,
                (&index_vec[i] + 1).into(),
            )
            .expect("invalid vss");
        println!("P{}'s share is {}",i,shared_keys.x_i.to_bigint());
        shared_keys_vec.push(shared_keys);
        dlog_proof_vec.push(dlog_proof);
    }
    //g*xi
    let pk_vec = dlog_proof_vec
        .iter()
        .map(|dlog_proof| dlog_proof.pk.clone())
        .collect::<Vec<Point<Bls12_381_1>>>();

    //对xi进行验证
    Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec).expect("bad dlog proof");

    let xi_vec = shared_keys_vec
        .iter()
        .take(usize::from(t + 1))
        .map(|shared_keys| shared_keys.x_i.clone())
        .collect::<Vec<Scalar<Bls12_381_1>>>();

    //重构秘密
    let x = vss_scheme_for_test[0]
        .clone()
        .reconstruct(&index_vec[0..=usize::from(t)], &xi_vec);
    let sum_u_i = party_keys_vec
        .iter()
        .fold(Scalar::<Bls12_381_1>::zero(), |acc, x| acc + &x.u_i);
    assert_eq!(x, sum_u_i);
    println!("Y:{:?}",y_sum.clone());
    println!("X:{}",x.clone().to_bigint());

    (
        party_keys_vec,
        shared_keys_vec,
        pk_vec,
        y_sum,
        vss_scheme_for_test[0].clone(),
    )

}

#[test]
fn test_keygen_t2_n4() {
    keygen_t_n_parties(2, 4);
}

