#!/system/bin/sh
# Automatically set device props for shared-hardware models and variants.


load_op7tpro()
{
    resetprop "ro.product.model" "OnePlus 7T Pro"
    resetprop "ro.product.name" "OnePlus7TPro"
    resetprop "ro.build.product" "OnePlus7TPro"
    resetprop "ro.product.device" "OnePlus7TPro"
    resetprop "ro.vendor.product.device" "OnePlus7TPro"
    resetprop "ro.display.series" "OnePlus 7T Pro"
}

load_op7tpro5g()
{
    resetprop "ro.product.model" "OnePlus 7T Pro 5G"
    resetprop "ro.product.name" "OnePlus7TProNR"
    resetprop "ro.build.product" "OnePlus7TProNR"
    resetprop "ro.product.device" "OnePlus7TProNR"
    resetprop "ro.vendor.product.device" "OnePlus7TProNR"
    resetprop "ro.display.series" "OnePlus 7T Pro 5G"
}

load_op7t()
{
    resetprop "ro.product.model" "OnePlus 7T"
    resetprop "ro.product.name" "OnePlus7T"
    resetprop "ro.build.product" "OnePlus7T"
    resetprop "ro.product.device" "OnePlus7T"
    resetprop "ro.vendor.product.device" "OnePlus7T"
    resetprop "ro.display.series" "OnePlus 7T"
}

project_codename=$(getprop ro.boot.project_codename)
project_name=$(getprop ro.boot.project_name)
echo "Running unified/variant script with codename '$project_codename' and project '$project_name'..." >> /tmp/recovery.log

case "$project_codename" in
    hotdogb)
        load_op7t
        ;;
    hotdogg)
        load_op7tpro5g
        ;;
    hotdog)
        load_op7tpro
        ;;
    *)
        case "$project_name" in
            18865)
                load_op7t
                ;;
            19801)
                load_op7tpro
                ;;
            *)
                # Unknown hardware must fail closed: keep the product identity
                # supplied by the bootloader/ROM instead of guessing a model.
                echo "Unknown hotdog variant; leaving product identity unchanged." >> /tmp/recovery.log
                ;;
        esac
        ;;
esac

exit 0
