package main

import "C"
import (
    "os"
    "os/exec"
    "bytes"
    "fmt"
    "flag"
    "time"
    "encoding/json"
    "strings"
    "strconv"
    qmp "github.com/digitalocean/go-qemu/qmp"
    )

type ret struct {
    err bool
    v uint
}

/*func lvcreate(c chan ret, plvmpath string, clvmname string) {

    out, err := exec.Command("lvcreate", "-s", "-L1G", "-n", clvmname, plvmpath).Output()

    if err != nil {
        c <- ret{true,0}
    } else {
        fmt.Printf("%s", out)
        c <- ret{false,0}
    }

    close(c)
}*/

func forkdisk(c chan ret, pdiskpath string, cdiskpath string) {
    out, err := exec.Command("qemu-img", "create", "-f", "qcow2", "-b", pdiskpath, cdiskpath).Output()

    if err != nil {
        c <- ret{true,0}
    } else {
        fmt.Printf("%s", out)
        c <- ret{false,0}
    }

    close(c)
}

func forkvm(c chan ret, pdomid int) {

    var stderrout bytes.Buffer
    cmd := exec.Command("xl", "fork-vm", "--launch-dm", "no", "-p", strconv.Itoa(pdomid))
    cmd.Stderr = &stderrout

    if err:= cmd.Run(); err != nil {
        c <- ret{true,0}
        close(c)
        return
    }

    fmt.Printf("%s", stderrout.String())
    c <- ret{false,0}

    close(c)
}

type StatusResult struct {
    ID     string `json:"id"`
    Return struct {
        Running    bool   `json:"running"`
        Singlestep bool   `json:"singlestep"`
        Status     string `json:"status"`
    } `json:"return"`
}

func qemu_savestate(c chan ret, domid int, savepath string) {
    if _, err := os.Stat(savepath); err == nil {
        c <- ret{false,0}
        return
    }

    //quit := []byte("{ \"execute\": \"quit\" }")
    socketpath := strings.Join([]string{"/var/run/xen/qmp-libxl-", strconv.Itoa(domid)}, "")
    monitor, err := qmp.NewSocketMonitor("unix", socketpath, 2*time.Second)

    if err != nil {
        c <- ret{true,0}
        return
    }

    monitor.Connect()
    defer monitor.Disconnect()

    savepath = strings.Join([]string{"\"", savepath, "\""}, "")

    cmdstring := strings.Join([]string{"{ \"execute\": \"xen-save-devices-state\", \"arguments\": { \"filename\": ", savepath, ", \"live\": false } }"},"")

    cmd := []byte(cmdstring)
    raw, err2 := monitor.Run(cmd)

    if err2 != nil {
        fmt.Println("error..")
    }

    var result StatusResult
    json.Unmarshal(raw, &result)

    fmt.Println(result.Return.Status)

    //monitor.Run(quit)
    c <- ret{false,0}
}

func main() {
    pdomidptr := flag.Int("parent-domid", -1, "parent-domid")
    savepathptr := flag.String("qemu-save-path", "", "qemu-save-path")
    //pdiskpathptr := flag.String("disk-parent-path", "", "disk-parent-path")
    //cdiskpathptr := flag.String("disk-clone-path", "", "disk-clone-path")

    flag.Parse()

    pdomid := *pdomidptr
    savepath := *savepathptr
    //pdiskpath := *pdiskpathptr
    //cdiskpath := *cdiskpathptr

    if pdomid < 0 {
        fmt.Println("Please specify a valid -parent-domid,", pdomid, "is invalid")
        os.Exit(1)
    }

    if strings.Compare(savepath, "") == 0 {
        fmt.Println("Please specify a valid -qemu-save-path")
        os.Exit(1)
    }

    //c1 := make(chan ret)
    c2 := make(chan ret)
    c3 := make(chan ret)

    //go forkdisk(c1, pdiskpath, cdiskpath)
    go forkvm(c2, pdomid)
    go qemu_savestate(c3, pdomid, savepath)

    for {
        select {
            //case r1 := <-c1:
            //    fmt.Println("Got r1: ", r1.err, r1.v)
            //    c1 = nil
            case <-c2:
            //    fmt.Println("Got r2: ", r2.err, r2.v)
                c2 = nil
            case <-c3:
            //    fmt.Println("Got r3: ", r3.err, r3.v)
                c3 = nil
        }

        //if c1 == nil && c2 == nil && c3 == nil {
        if c2 == nil && c3 == nil {
            break
        }
    }
}
