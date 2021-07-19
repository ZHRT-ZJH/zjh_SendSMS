<?php
namespace MwempSendSMS\lib;
/**
 * Created by PhpStorm.
 * Date: 2021-7-19
 * Time: 9:45
 * @功能概要：梦网统一认证管理类
 */
class SmsSendConn
{
    /**
     * API请求地址
     */
    private $BaseUrlArr = [
        'query_msisdn' => ['url' => 'https://oneclick.mwemp.com:7197/svcapi/v1/query_msisdn', 'type' => 'POST'], //取号接口
        'verify_msisdn' => ['url' => 'https://oneclick.mwemp.com:7197/svcapi/v1/verify_msisdn', 'type' => 'POST'], //验号接口
    ];

    /**
     * 加解密用的方式
     */
    private $encryptionMode = "AES-128-CBC";

    private $key = "";

    private $iv = "";

    public $ERROR_310099=-310099;//http请求失败错误码

    public function  __construct()
    {
        $this->key = hash('sha256', $this->key);
    }

    /**
     * 取号接口
     * $url：请求地址
     * $post_data：请求数据
     */
    public function query_msisdn($data)
    {
        try {
            $data['timestamp'] = date('mdHis', time());//时间戳
            $data['checksum'] = strtoupper( printf("%u", crc32(json_encode($data) ) ) ); //报文主体明文的CRC32校验和（大写）
            $data['payload'] = $this->encrypt($data); //报文主体的密文
            $post_data = json_encode($data);//将数组转化为JSON格式
            $result = $this->connection($this->BaseUrlArr['query_msisdn']['url'], $post_data);//根据请求类型进行请求
            return $result;//返回请求结果
        }catch (Exception $e) {
            print_r($e->getMessage());  //输出捕获的异常消息
        }
    }

    /**
     * 验号接口
     * $url：请求地址
     * $post_data：请求数据
     */
    public function verify_msisdn($data)
    {
        try {
            $data['timestamp'] = date('mdHis', time());//时间戳
            $data['checksum'] = strtoupper( printf("%u", crc32(json_encode($data) ) ) ); //报文主体明文的CRC32校验和（大写）
            $data['payload'] = $this->encrypt($data); //报文主体的密文
            $post_data = json_encode($data);//将数组转化为JSON格式
            $result = $this->connection($this->BaseUrlArr['query_msisdn']['url'], $post_data);//根据请求类型进行请求
            return $result;//返回请求结果
        }catch (Exception $e) {
            print_r($e->getMessage());  //输出捕获的异常消息
        }
    }

    /**
     * AES CBC模式PKCS7 128位加密
     */
    public function encrypt($data)
    {
        try{
            return base64_encode(openssl_encrypt($data, $this->encryptionMode, $this->key,true, $this->iv));
        }catch (Exception $e) {
            print_r($e->getMessage());  //输出捕获的异常消息
        }
    }

    /**
     * AES CBC模式PKCS7 128位解密
     */
    public function decrypt($data)
    {
        try{
            return openssl_decrypt(base64_decode($data), $this->encryptionMode, $this->key, true, $this->iv);
        }catch (Exception $e) {
            print_r($e->getMessage());  //输出捕获的异常消息
        }
    }

    /**
     * 短连接请求方法
     * $url：请求地址
     * $post_data：请求数据
     */
    private function connection($url,$post_data)
    {
        try {
            $attributes = array('Accept:text/plain;charset=utf-8', 'Content-Type:application/json', 'charset=utf-8', 'Expect:', 'Connection: Close');//请求属性
            $ch = curl_init();//初始化一个会话
            /* 设置验证方式 */
            curl_setopt($ch, CURLOPT_HTTPHEADER, $attributes);//设置访问
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);//设置返回结果为流
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);//设置请求超时时间
            curl_setopt($ch, CURLOPT_TIMEOUT, 60);//设置响应超时时间
            /* 设置通信方式 */
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);//使用urlencode格式请求

            $result = curl_exec($ch);//获取返回结果集
            $result=preg_replace('/\"msgid":(\d{1,})./', '"msgid":"\\1",', $result);//正则表达式匹配所有msgid转化为字符串
            $result = json_decode($result, true);//将返回结果集json格式解析转化为数组格式

            //解密
            $result = $this->decrypt($result);

            //获取错误代码
            $resultMsg = require("resultMsg.php");
            $result['result_msg'] = $resultMsg[$result['result']] ?? '其他错误';

            if (curl_errno($ch) !== 0) //网络问题请求失败
            {
                $result['result'] = $this->ERROR_310099;
                $result['result_msg'] = 'http请求失败';
                curl_close($ch);//关闭请求会话
            } else {
                $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                if ($statusCode != 200||!isset($result['result']))//域名问题请求失败或不存在返回结果
                {
                    $result='';//清空result集合
                    $result['result'] = $this->ERROR_310099;
                    $result['result_msg'] = 'http请求失败';
                }
                curl_close($ch);//关闭请求会话
            }

            return $result;

        } catch (Exception $e) {
            print_r($e->getMessage());//输出捕获的异常消息
            $result['result'] = $this->ERROR_310099;//返回http请求错误代码
            $result['result_msg'] = 'http请求失败';
            return $result;
        }
    }
}
?>